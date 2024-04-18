ALTER TABLE users ADD COLUMN secret TEXT;


Create blog with authentication 

Database name = userblog
Table name = users

CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username VARCHAR(255) UNIQUE NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  title VARCHAR(255),
  date DATE,
  content TEXT,
  picurl VARCHAR(255)
);
