import hre from "hardhat";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  const EvidenceLedger = await hre.ethers.getContractFactory("EvidenceLedger");
  const ledger = await EvidenceLedger.deploy();
  await ledger.waitForDeployment();
  
  const contractAddress = await ledger.getAddress();
  console.log("🛡️ EvidenceLedger Smart Contract deployed to:", contractAddress);

  const deploymentData = {
    address: contractAddress,
    network: "localhost:8545",
    deployedAt: new Date().toISOString()
  };

  const outputDir = path.join(__dirname, "../../backend/app/core");
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  
  const outputPath = path.join(outputDir, "contract_info.json");
  fs.writeFileSync(outputPath, JSON.stringify(deploymentData, null, 2));
  console.log("✅ Contract configuration exported to backend/app/core/contract_info.json");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});