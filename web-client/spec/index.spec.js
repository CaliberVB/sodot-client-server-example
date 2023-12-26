import { runClient} from '../src/index.js';

describe("Test Client with Server", () => {
    it("Ed25519 and then Ecdsa", async () => {
        const starTime = new Date().getTime() / 1000;
        console.log("Starting...");
        await runClient('ecdsa', 'fdfd10fc-84de-43d8-84ce-eb42d2cb62a1');
        console.log("End----------------------------------------------------------------");
        const endTime = new Date().getTime() / 1000;
        console.log("----------------------------------------------------------------",Math.abs(endTime - starTime));
        // console.log("Ecdsa done!");
        // await runClient('ed25519', 'fdfd10fc-84de-43d8-84ce-eb42d2cb62a1');
        // console.log('Ed25519 done!');
    });
});