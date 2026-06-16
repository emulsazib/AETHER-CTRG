// Seed the Neo4j threat-correlation graph from the shared graphSeed.
// No-op-with-warning if Neo4j is unreachable (the in-memory graph self-seeds).
import { connectNeo4j, isNeo4jConnected, getDriver, disconnectNeo4j } from '../config/neo4j.js';
import { graphSeed } from './graphSeedData.js';

export async function seedNeo4j() {
  await connectNeo4j();
  if (!isNeo4jConnected()) {
    console.warn('[seed:neo4j] Neo4j unreachable — skipping (memory graph self-seeds).');
    return;
  }

  const session = getDriver().session();
  try {
    // Clean slate for repeatable seeding (dev only).
    await session.run('MATCH (n) DETACH DELETE n');

    // Create nodes — label is interpolated (controlled, from our seed file).
    for (const node of graphSeed.nodes) {
      await session.run(
        `CREATE (n:${node.label} {id: $id, name: $name})
         SET n += $props`,
        { id: node.id, name: node.name, props: node.props || {} },
      );
    }

    // Create relationships — type is interpolated (controlled, from seed file).
    for (const edge of graphSeed.edges) {
      await session.run(
        `MATCH (a {id: $source}), (b {id: $target})
         CREATE (a)-[r:${edge.type}]->(b)
         SET r += $props`,
        { source: edge.source, target: edge.target, props: edge.props || {} },
      );
    }

    console.log(
      `[seed:neo4j] created ${graphSeed.nodes.length} nodes, ${graphSeed.edges.length} edges.`,
    );
  } finally {
    await session.close();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  seedNeo4j().then(() => disconnectNeo4j());
}
