import KeyPair from "./support/key_pair";
import { ConfigBuilder, Controller, KeyType, PublicKey, SignatureBuilder, SignatureType } from "index";
import { sleep } from "@napi-rs/package-template";
import { assert } from "console";
import { dirSync} from "tmp";

describe("Managing controller", () => {
  it("", async () => {
    const tmpdir = dirSync();
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();
    const nextNextKeyManager = new KeyPair();

    let config = new ConfigBuilder().withDbPath(tmpdir.name).build();
    let controller = new Controller(config);

    let keyType = KeyType.Ed25519;
    let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));
    let pk3 = new PublicKey(keyType, Buffer.from(nextNextKeyManager.pubKey));

    console.log(pk.getKey())

    let inceptionEvent = await controller.incept(
      [pk.getKey()],
      [pk2.getKey()],
      [],
      0 
    );
    console.log(inceptionEvent.toString())

    let signature = currentKeyManager.sign(inceptionEvent);

    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

    let inceptedController = await controller.finalizeInception(
      inceptionEvent,
      [signaturePrefix.getSignature()]
    );

    console.log(await inceptedController.getKel())

    let rotationEvent = await inceptedController.rotate([pk2.getKey()], [pk3.getKey()], [], [], 0);
    console.log(rotationEvent.toString())

    let signature2 = nextKeyManager.sign(rotationEvent);
    let signaturePrefix2 = new SignatureBuilder(sigType, Buffer.from(signature2));

    await inceptedController.finalizeEvent(rotationEvent, [signaturePrefix2.getSignature()])

    let interactionEvent = await inceptedController.anchor(["E3WFzw8WgDMFPpup9UJI3Wwu41h16NNJVzkKclj2_6Rc"]);
    let signature3 = nextKeyManager.sign(interactionEvent);
    let signaturePrefix3 = new SignatureBuilder(sigType, Buffer.from(signature3));

    inceptedController.finalizeEvent(interactionEvent, [signaturePrefix3.getSignature()])

    console.log(await inceptedController.getKel())

    let stringData = `{"data":"important data"}`
    let dataToSign = Buffer.from(stringData)
    let dataSignature = nextKeyManager.sign(dataToSign);
    let dataSignaturePrefix = new SignatureBuilder(sigType, Buffer.from(dataSignature));
    let attachedSignature = await inceptedController.signData(dataSignaturePrefix.getSignature());

    let signedACDC = stringData.concat(attachedSignature);
    console.log(signedACDC)

    assert(controller.verifyFromCesr(signedACDC))
  });
});

describe("Witness communication", () => {
  it("", async () => {
    const tmpdir = dirSync();
    const currentKeyManager = new KeyPair();
    const nextKeyManager = new KeyPair();

    let config = new ConfigBuilder().withDbPath(tmpdir.name).build();
    let controller = new Controller(config);

    let keyType = KeyType.Ed25519;
    let pk = new PublicKey(keyType, Buffer.from(currentKeyManager.pubKey));
    let pk2 = new PublicKey(keyType, Buffer.from(nextKeyManager.pubKey));

    console.log(pk.getKey())

    let inceptionEvent = await controller.incept(
      [pk.getKey()],
      [pk2.getKey()],
      [`{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://witness1.sandbox.argo.colossi.network"}`],
      1
    );
    console.log(inceptionEvent.toString())

    let signature = currentKeyManager.sign(inceptionEvent);

    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

    let inceptedController = await controller.finalizeInception(
      inceptionEvent,
      [signaturePrefix.getSignature()]
    );

    await inceptedController.notifyWitnesses();

    let queryMailbox = await inceptedController.queryMailbox(["BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"]);
    let querySignaturePrefix

    Promise.all(queryMailbox.map(async(element) => {
        querySignaturePrefix = new SignatureBuilder(sigType, Buffer.from(currentKeyManager.sign(element)))
        await inceptedController.finalizeQuery(Buffer.from(element), querySignaturePrefix.getSignature())
      }
      ));
   
    await new Promise(r => setTimeout(r, 2000));
    console.log(await inceptedController.getKel())

    let stringData = `{"data":"important data"}`
    let dataToSign = Buffer.from(stringData)
    let dataSignature = currentKeyManager.sign(dataToSign);
    let dataSignaturePrefix = new SignatureBuilder(sigType, Buffer.from(dataSignature));
    let attachedSignature = await inceptedController.signData(dataSignaturePrefix.getSignature());

    let signedACDC = stringData.concat(attachedSignature);
    console.log(signedACDC)

    assert(controller.verifyFromCesr(signedACDC))
  });
});
