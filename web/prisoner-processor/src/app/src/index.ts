import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { zValidator } from '@hono/zod-validator'
import { z } from 'zod';
import { createHmac, randomBytes } from 'crypto';
import { readFileSync, existsSync } from 'fs';
import { stringify } from 'yaml';

const SECRET_KEY = randomBytes(64);
const SIGNED_PREFIX = "signed.";
const OUTPUT_YAML_FOLDER = "/app-data/yamls";
const BANNED_STRINGS = [
  "app", "src", ".ts", "node", "package", "bun", "home", "etc", "usr", "opt", "tmp", "index", ".sh"
];

const app = new Hono();

const cache: any = {};

const getSignature = (data: any): string => {
  const toSignArray = Object.entries(data).map(([k, v]) => `${k}=${v}`);
  toSignArray.sort();
  return createHmac('sha256', SECRET_KEY)
    .update(toSignArray.join("&"))
    .digest("hex");
};

const hasValidSignature = (data: any, signature: string): boolean => {
  const signedInput = getSignature(data);
  return signedInput === signature
};

const getSignedData = (data: any): any => {
  const signedParams: any = {};
  for (const param in data) {
    if (param.startsWith(SIGNED_PREFIX)) {
      const keyName = param.slice(SIGNED_PREFIX.length);
      signedParams[keyName] = data[param];
    }
  }
  return signedParams;
};

const checkIfContainsBannedString = (outputFile: string): boolean => {
  for (const banned of BANNED_STRINGS) {
    if (outputFile.includes(banned)) {
      return true
    }
  }
  return false;
}

const convertJsonToYaml = (data: any, outputFileString: string): boolean => {
  if (checkIfContainsBannedString(outputFileString)) {
    return false
  }
  const filePath = `${OUTPUT_YAML_FOLDER}/${outputFileString}`;
  const outputFile = Bun.file(filePath);
  // Prevent accidental overwriting of app files
  if (existsSync(outputFile)) {
    return false
  }

  try {
    const yamlData = stringify(data);
    Bun.write(outputFile, yamlData);
    return true;
  } catch (error) {
    console.error(error)
    return false;
  }
};

const requestSchema = z.object({
  data: z.record(z.string(), z.any()),
  signature: z.string().length(64)
});

app.post('/convert-to-yaml',
  bodyLimit({
    maxSize: 50 * 1024, // 50kb limit
  }),
  zValidator('json', requestSchema),
  (c) => {
    try {
      const body = c.req.valid('json');
      const data = body.data;
      const signedData = getSignedData(data)
      const signature = body.signature;
      if (!hasValidSignature(signedData, signature)) {
        return c.json({ msg: "signatures do no match!" }, 400);
      }
      const outputPrefix = z.string().parse(signedData.outputPrefix ?? "prisoner");
      const outputFile = `${outputPrefix}-${randomBytes(8).toString("hex")}.yaml`;
      if (convertJsonToYaml(data, outputFile)) {
        return c.json({ msg: outputFile });
      } else {
        return c.json({ msg: "failed to convert JSON" }, 500);
      }
    } catch (error) {
      console.error(error);
      return c.json({ msg: "why you send me a bad request???" }, 400);
    }
  }
);

app.get('/examples', (c) => {
  try {
    const examplePrisoners = cache.examplePrisoners ?? (() => {
      const prisoners = [];
      for (const path of ["jeff.json", "sharon.json", "kevin.json"]) {
        const fullPath = `/app/examples/${path}`;
        const json = JSON.parse(readFileSync(fullPath).toString());
        prisoners.push({
          data: json,
          signature: getSignature(getSignedData(json))
        });
      }
      cache.examplePrisoners = prisoners;
      return prisoners;
    })();
    return c.json({ examples: examplePrisoners });
  } catch (error) {
    return c.json({ msg: "you really goofed something up lol" })
  }
});

export default {
  port: 1337,
  fetch: app.fetch,
}
