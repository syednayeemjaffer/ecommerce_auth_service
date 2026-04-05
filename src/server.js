require("dotenv").config();
const app = require("./app");
require("./config/db");
require("./config/redis");
const PORT = process.env.PORT || 5001;


const startServer = async () => {
    app.listen(PORT, () => {
        console.log(`🚀 Auth service running on port ${PORT}`);
    });
};

startServer();
