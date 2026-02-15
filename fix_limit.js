require('dotenv').config();
const { Client } = require('@elastic/elasticsearch');

const ES_NODE = process.env.ELASTICSEARCH_NODE || 'http://localhost:9200';
const ES_INDEX = process.env.ELASTICSEARCH_INDEX || 'cape-direct-v2';
const ES_USERNAME = process.env.ELASTICSEARCH_USERNAME;
const ES_PASSWORD = process.env.ELASTICSEARCH_PASSWORD;

const client = new Client({
    node: ES_NODE,
    auth: { username: ES_USERNAME, password: ES_PASSWORD },
    tls: { rejectUnauthorized: false }
});

async function run() {
    try {
        console.log(`Updating max_result_window for index '${ES_INDEX}'...`);
        
        const response = await client.indices.putSettings({
            index: ES_INDEX,
            body: {
                "index.max_result_window": 100000
            }
        });

        console.log('Update response:', response);
    } catch (err) {
        console.error('Error updating settings:', JSON.stringify(err, null, 2));
    }
}

run();
