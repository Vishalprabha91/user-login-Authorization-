const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const app = express();

const dbPath = path.join(__dirname, "covid19IndiaPortal.db");
app.use(express.json());

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    app.listen(3001, () => {
      console.log("Server running at http://localhost:3001");
    });
  } catch (e) {
    console.error(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

const convertStateDbObjectToResponseObject = (dbObject) => ({
  stateId: dbObject.state_id,
  stateName: dbObject.state_name,
  population: dbObject.population,
});

const convertDistrictDbObjectToResponseObject = (dbObject) => ({
  districtId: dbObject.district_id,
  districtName: dbObject.district_name,
  stateId: dbObject.state_id,
  cases: dbObject.cases,
  cured: dbObject.cured,
  active: dbObject.active,
  deaths: dbObject.deaths,
});

const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
  }
  if (jwtToken === undefined) {
    response.status(401).send("Invalid JWT Token");
  } else {
    jwt.verify(
      jwtToken,
      process.env.JWT_SECRET || "default_secret",
      (error, payload) => {
        if (error) {
          response.status(401).send("Invalid JWT Token");
        } else {
          next();
        }
      }
    );
  }
};

app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM user WHERE username = ?`;
  const dbUser = await db.get(selectUserQuery, [username]);
  if (!dbUser) {
    response.status(400).send("Invalid user");
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched) {
      const payload = {
        username: username,
      };
      const jwtToken = jwt.sign(
        payload,
        process.env.JWT_SECRET || "default_secret"
      );
      response.send({ jwtToken });
    } else {
      response.status(400).send("Invalid password");
    }
  }
});

app.get("/states/", authenticateToken, async (request, response) => {
  try {
    const getStateArray = `
      SELECT * FROM state;
    `;
    const stateArray = await db.all(getStateArray);
    response.send(stateArray.map(convertStateDbObjectToResponseObject));
  } catch (error) {
    console.error(`Error fetching states: ${error.message}`);
    response.status(500).send("Internal Server Error");
  }
});

app.get("/states/:stateId/", authenticateToken, async (request, response) => {
  const { stateId } = request.params;
  const getStateQuery = `
    SELECT * FROM state
    WHERE state_id = ?;
  `;
  const state = await db.get(getStateQuery, [stateId]);
  response.send(convertStateDbObjectToResponseObject(state));
});

app.get(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const getDistrictQuery = `
    SELECT * FROM district
    WHERE district_id = ?;
  `;
    const district = await db.get(getDistrictQuery, [districtId]);
    response.send(convertDistrictDbObjectToResponseObject(district));
  }
);

app.post("/districts/", authenticateToken, async (request, response) => {
  const { stateId, districtName, cases, cured, active, deaths } = request.body;

  const addDistrictQuery = `
    INSERT INTO district (state_id, district_name, cases, cured, active, deaths)
    VALUES (?, ?, ?, ?, ?, ?);
  `;

  try {
    await db.run(addDistrictQuery, [
      stateId,
      districtName,
      cases,
      cured,
      active,
      deaths,
    ]);
    response.send("District Successfully Added");
  } catch (error) {
    console.error(`Error adding district: ${error.message}`);
    response.status(500).send("Internal Server Error");
  }
});

app.delete(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const deleteDistrictQuery = `DELETE FROM district WHERE district_id = ?`;

    try {
      await db.run(deleteDistrictQuery, [districtId]);
      response.send("District Removed");
    } catch (error) {
      console.error(`Error deleting district: ${error.message}`);
      response.status(500).send("Internal Server Error");
    }
  }
);

app.put(
  "/districts/:districtId/",
  authenticateToken,
  async (request, response) => {
    const { districtId } = request.params;
    const districtDetails = request.body;

    const {
      stateId,
      districtName,
      cases,
      cured,
      active,
      deaths,
    } = districtDetails;

    const updateDistrictQuery = `
    UPDATE district
    SET
      state_id=?, district_name=?, cases=?, cured=?, active=?, deaths=?
    WHERE district_id=?;
  `;
    await db.run(updateDistrictQuery, [
      stateId,
      districtName,
      cases,
      cured,
      active,
      deaths,
      districtId,
    ]);
    response.send("District Details Updated");
  }
);

app.get(
  "/states/:stateId/stats/",
  authenticateToken,
  async (request, response) => {
    const stateId = request.params.stateId;
    const getStateStatsQuery = `
    SELECT
      SUM(cases) as totalCases,
      SUM(cured) as totalCured,
      SUM(active) as totalActive,
      SUM(deaths) as totalDeaths
    FROM
      district
    WHERE
      state_id = ?`;

    const stats = await db.get(getStateStatsQuery, [stateId]);
    response.send({
      totalCases: stats.totalCases,
      totalCured: stats.totalCured,
      totalActive: stats.totalActive,
      totalDeaths: stats.totalDeaths,
    });
  }
);

module.exports = app;
