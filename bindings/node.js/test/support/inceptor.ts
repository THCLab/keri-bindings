import KeyPair from "./key_pair";
import {ConfigBuilder, Controller, IdController, KeyType, PublicKey, SignatureBuilder, SignatureType} from "index";
import { fstat} from "fs";

export default async (db_path: string, oobis: string[]): Promise<[IdController, KeyPair]> => {
  const currentKeyManager = new KeyPair();
  // nextKeyManager is required for prerotation to be known
  const nextKeyManager = new KeyPair();

  let pk = new PublicKey(KeyType.Ed25519, Buffer.from(currentKeyManager.pubKey));
  let pk2 = new PublicKey(KeyType.Ed25519, Buffer.from(nextKeyManager.pubKey));

  let config = new ConfigBuilder().withDbPath(db_path)
    .build();
  console.log(config);
  let controller = new Controller(config);

  let inceptionEvent = await controller.incept(
    [pk.getKey()],
    [pk2.getKey()],
    oobis,
    oobis.length
  );

  let signature = currentKeyManager.sign(inceptionEvent);

  let sigType = SignatureType.Ed25519Sha512;
  let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

  let identifierController = await controller.finalizeInception(
    inceptionEvent,
    [signaturePrefix.getSignature()]
  );

  return [ identifierController, currentKeyManager ];
};
