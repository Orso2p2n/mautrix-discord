package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	dbutil "go.mau.fi/util/dbutil"

	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/olm"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (puppet *Puppet) GetOlmMachine() (*crypto.OlmMachine, error) {
	puppet.olmLock.Lock()
	defer puppet.olmLock.Unlock()
	if puppet.olmMachine != nil {
		return puppet.olmMachine, nil
	}
	err := puppet.initOlmMachine()
	return puppet.olmMachine, err
}

func (puppet *Puppet) initOlmMachine() error {
	br := puppet.bridge
	log := puppet.log.With().Str("component", "puppet_crypto").Logger()

	client := br.AS.NewMautrixClient(puppet.MXID)
	deviceID := id.DeviceID("DISCORD_" + puppet.ID)

	if err := client.CreateDeviceMSC4190(deviceID, "Discord bridge"); err != nil {
		return fmt.Errorf("failed to create puppet device via MSC4190: %w", err)
	}

	cryptoStore := crypto.NewSQLCryptoStore(
		br.Bridge.DB,
		dbutil.ZeroLogger(log.With().Str("db_section", "puppet_crypto").Logger()),
		puppet.MXID.String(),
		client.DeviceID,
		[]byte(br.CryptoPickleKey),
	)

	machine := crypto.NewOlmMachine(client, &log, cryptoStore, br.StateStore)
	if err := machine.Load(); err != nil {
		return fmt.Errorf("failed to load puppet Olm machine: %w", err)
	}

	if !machine.GetAccount().Shared {
		if err := machine.ShareKeys(context.Background(), 0); err != nil {
			return fmt.Errorf("failed to upload puppet device keys: %w", err)
		}
	}

	if err := puppet.initCrossSigning(machine, br.CryptoPickleKey); err != nil {
		log.Warn().Err(err).Msg("Failed to set up cross-signing for puppet, messages will show unverified warning")
	}

	puppet.olmMachine = machine
	log.Debug().Str("device_id", client.DeviceID.String()).Msg("Initialized per-puppet Olm machine")
	return nil
}

func (puppet *Puppet) initCrossSigning(machine *crypto.OlmMachine, pickleKey string) error {
	identityKey := machine.GetAccount().IdentityKey()

	masterSeed := deriveCrossSigningSeed([]byte(pickleKey), []byte(identityKey), "master")
	selfSeed := deriveCrossSigningSeed([]byte(pickleKey), []byte(identityKey), "self_signing")
	userSeed := deriveCrossSigningSeed([]byte(pickleKey), []byte(identityKey), "user_signing")

	masterKey, err := olm.NewPkSigningFromSeed(masterSeed)
	if err != nil {
		return fmt.Errorf("failed to create master key from seed: %w", err)
	}
	selfKey, err := olm.NewPkSigningFromSeed(selfSeed)
	if err != nil {
		return fmt.Errorf("failed to create self-signing key from seed: %w", err)
	}
	userKey, err := olm.NewPkSigningFromSeed(userSeed)
	if err != nil {
		return fmt.Errorf("failed to create user-signing key from seed: %w", err)
	}

	csKeys := &crypto.CrossSigningKeysCache{
		MasterKey:      masterKey,
		SelfSigningKey: selfKey,
		UserSigningKey: userKey,
	}

	if err = machine.PublishCrossSigningKeys(csKeys, nil); err != nil {
		return fmt.Errorf("failed to publish cross-signing keys: %w", err)
	}

	device := &id.Device{
		UserID:    puppet.MXID,
		DeviceID:  machine.Client.DeviceID,
		SigningKey: id.SigningKey(machine.GetAccount().SigningKey()),
	}
	if err = machine.SignOwnDevice(device); err != nil {
		return fmt.Errorf("failed to self-sign puppet device: %w", err)
	}

	return nil
}

func deriveCrossSigningSeed(pickleKey, identityKey []byte, label string) []byte {
	h := hmac.New(sha256.New, pickleKey)
	h.Write(identityKey)
	h.Write([]byte{':'})
	h.Write([]byte(label))
	return h.Sum(nil)
}

func puppetEncrypt(machine *crypto.OlmMachine, stateStore interface {
	GetRoomJoinedOrInvitedMembers(id.RoomID) ([]id.UserID, error)
}, roomID id.RoomID, evtType event.Type, content *event.Content) error {
	ctx := context.TODO()
	encrypted, err := machine.EncryptMegolmEvent(ctx, roomID, evtType, content)
	if err != nil {
		if !crypto.IsShareError(err) {
			return err
		}
		users, membersErr := stateStore.GetRoomJoinedOrInvitedMembers(roomID)
		if membersErr != nil {
			return fmt.Errorf("failed to get room members: %w", membersErr)
		}
		if shareErr := machine.ShareGroupSession(ctx, roomID, users); shareErr != nil {
			return fmt.Errorf("failed to share group session: %w", shareErr)
		}
		if encrypted, err = machine.EncryptMegolmEvent(ctx, roomID, evtType, content); err != nil {
			return fmt.Errorf("failed to encrypt event after re-sharing session: %w", err)
		}
	}
	if encrypted != nil {
		content.Parsed = encrypted
		content.Raw = nil
	}
	return nil
}
