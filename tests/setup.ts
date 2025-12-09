// Load environment variables from .env file before running tests
import { config } from 'dotenv';
import { resolve } from 'path';

// Load .env file from the project root
config({ path: resolve(__dirname, '../.env') });

