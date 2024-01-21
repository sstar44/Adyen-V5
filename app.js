const jose = require("node-jose");
const express = require("express");
const app = express();
const cors = require("cors");

app.use(cors());

app.get("/", function (req, res) {
  res.sendFile(__dirname + "/index.html");
});

app.use(
  express.urlencoded({
    extended: false,
    limit: 10000,
    parameterLimit: 1000,
  }),
);

async function parseKey(t) {
  function to(e) {
    return (function (e) {
      var t = e;
      for (var r = [], n = 0; n < t.length; n += 32768)
        r.push(String.fromCharCode.apply(null, t.subarray(n, n + 32768)));
      return btoa(r.join(""));
    })(e)
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }

  function ro(e) {
    if (!e) return new Uint8Array(0);
    e.length % 2 == 1 && (e = "0" + e);
    for (var t = e.length / 2, r = new Uint8Array(t), n = 0; n < t; n++)
      r[n] = parseInt(e.substr(2 * n, 2), 16);
    return r;
  }

  const r = t.split("|"); // Key parts
  const n = r[0]; // Exponent
  const o = r[1]; // RSA public key
  const i = ro(n);
  const a = ro(o);
  const c = to(i);
  const s = to(a);

  return jose.JWK.asKey({
    kty: "RSA",
    kid: "asf-key", // kid used in Adyen script
    e: c,
    n: s,
  });
}

(async () => {})();

app.post("/enc", async (req, res) => {
  const referrerx = decodeURI(req.body.referrer);
  const keyx = req.body.key;
  const cardx = req.body.card;
  const monthx = req.body.month;
  const yearx = req.body.year;
  const cvcx = req.body.cvc;
  const card1 = cardx.substring(0, 4);
  const card2 = cardx.substring(4, 8);
  const card3 = cardx.substring(8, 12);
  const card4 = cardx.substring(12, 16);

  async function encrypt(pubKey, fieldName, value, generationTime) {
    const formattedGenerationTime =
      generationTime.toISOString().split(".")[0] + "Z";

    let data;
    switch (fieldName) {
      case "number":
        data = {
          number: value,
          activate: "3",
          deactivate: "1",
          generationtime: formattedGenerationTime,
          numberBind: "1",
          numberFieldBlurCount: "1",
          numberFieldClickCount: "1",
          numberFieldFocusCount: "3",
          numberFieldKeyCount: "2",
          numberFieldLog:
            "fo@5956,cl@5960,bl@5973,fo@6155,fo@6155,Md@6171,KL@6173,pa@6173",
          numberFieldPasteCount: "1",
          referrer: referrerx,
        };
        break;

      case "expiryMonth":
        data = {
          expiryMonth: value,
          generationtime: formattedGenerationTime,
        };
        break;

      case "expiryYear":
        data = {
          expiryYear: value,
          generationtime: formattedGenerationTime,
        };
        break;

      case "cvc":
        data = {
          activate: "1",
          cvc: value,
          cvcBind: "1",
          cvcFieldClickCount: "1",
          cvcFieldFocusCount: "2",
          cvcFieldKeyCount: "4",
          cvcFieldLog:
            "fo@20328,fo@20328,cl@20329,KN@20344,KN@20347,KN@20349,KN@20351",
          generationtime: formattedGenerationTime,
          referrer: referrerx,
        };
        break;

      default:
        throw new Error("Invalid fieldName " + fieldName);
    }

    return jose.JWE.createEncrypt(
      {
        format: "compact",
        contentAlg: "A256CBC-HS512",
        fields: {
          alg: "RSA-OAEP",
          enc: "A256CBC-HS512",
          version: "1",
        },
      },
      { key: pubKey, reference: false },
    )
      .update(JSON.stringify(data))
      .final();
  }
  const key = await parseKey(keyx);
  const generationTime = new Date();

  const data = await Promise.all([
    encrypt(
      key,
      "number",
      `${card1} ${card2} ${card3} ${card4}`,
      generationTime,
    ),
    encrypt(key, "expiryMonth", monthx, generationTime),
    encrypt(key, "expiryYear", yearx, generationTime),
    encrypt(key, "cvc", cvcx, generationTime),
  ]);

  res.send(
    JSON.stringify({
      encryptedCardNumber: data[0],
      encryptedExpiryMonth: data[1],
      encryptedExpiryYear: data[2],
      encryptedSecurityCode: data[3],
    }),
  );
});

app.listen(3000, () => {
  console.log(`Example app listening on port 3000`);
});
