import { expect, should } from "chai";
import { countEvents } from "./support/kel";
import inceptor from "./support/inceptor";
import {SignatureBuilder, SignatureType} from "index";
import { dirSync} from "tmp";

describe("Anchoring", () => {
  it("Allows for anchoring one digest", async () => {
 
    const tmpobj = dirSync();


    let [ controller, currentKeyManager ] = await inceptor(
      tmpobj.name,
      []
    );

    let interactionEvent = await controller.anchor(["E6ISnmMK-TfP0uN2lLp5vL6JxxBNjXLZ7bpDBkjxngdE"])

    let signature = currentKeyManager.sign(interactionEvent);

    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

    await controller.finalizeEvent(
      interactionEvent,
      [signaturePrefix.getSignature()]
    );

    expect(countEvents(await controller.getKel())).to.eq(2);

  });

  it("Allows for anchoring multiple digests into one event", async () => {
    const tmpobj = dirSync();
    let [ controller, currentKeyManager ] = await inceptor(tmpobj.name, []);

    let firstDigest = "ENkA8MRYbPDcdSNuv5qrvVXTQl7KDo95enNpUGKXtIha";
    let secondDigest = "EK7-JEbML0yyuRk1PW0jRJEUKJC6W2WeES6FV5ykKJdL";
    let thirdDigest = "E6ISnmMK-TfP0uN2lLp5vL6JxxBNjXLZ7bpDBkjxngdE";

    let interactionEvent = await controller.anchor([ firstDigest, secondDigest, thirdDigest ]);

    let signature = currentKeyManager.sign(interactionEvent);
    let sigType = SignatureType.Ed25519Sha512;
    let signaturePrefix = new SignatureBuilder(sigType, Buffer.from(signature));

    let result = await controller.finalizeEvent(
      interactionEvent,
      [signaturePrefix.getSignature()]
    );

    let kel = await controller.getKel();
    expect(countEvents(kel)).to.eq(2);

    // expect(controller.isAnchored(firstDigest));
    // expect(controller.isAnchored(secondDigest));
    // expect(controller.isAnchored(thirdDigest));
  });

  describe("negative", () => {
    it("fails for not recognized digest format", async() => {
      const tmpdir = dirSync();
      let [ controller, currentKeyManager ] = await inceptor(tmpdir.name, []);

      try {
        await controller.anchor([ "whatever" ]);
      } catch (error) {
        expect(error.message).to.equal("Can't parse sai prefix");// .should.have.value("Can't parse sai prefix");
      }
      });
  });
});
