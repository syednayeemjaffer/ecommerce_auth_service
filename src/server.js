require("dotenv").config();
const app = require("./app");
require("./config/db");
require("./config/redis");
const initTables = require("./utils/initTables");
const PORT = process.env.PORT || 5001;


const startServer = async () => {
    await initTables();
    app.listen(PORT, () => {
        console.log(`🚀 Auth service running on port ${PORT}`);
    });
};

startServer();
