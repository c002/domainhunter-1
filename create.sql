CREATE DATABASE domainhunter;
CREATE USER 'domainhunter'@'localhost' IDENTIFIED BY 'domainhunter42';
GRANT ALL PRIVILEGES ON * . * TO 'domainhunter'@'localhost';
FLUSH PRIVILEGES;

USE domainhunter;
CREATE TABLE domainhunts (
    auto_id INTEGER NOT NULL AUTO_INCREMENT,
    fqdn VARCHAR(2048) NOT NULL,
    uuid VARCHAR(37) NOT NULL,
    s_dt DATETIME,
    PRIMARY KEY (auto_id)
    );


CREATE TABLE dns_records (
    auto_id INTEGER NOT NULL AUTO_INCREMENT,
    uuid VARCHAR(37) NOT NULL,
    uuid_parent VARCHAR(37),
    fqdn VARCHAR(2048) NOT NULL,
    r_type VARCHAR(8) NOT NULL,
    value VARCHAR(1000000),
    s_dt DATETIME,
    q_dt DATETIME,
    r_dt DATETIME,
    PRIMARY KEY (auto_id)
    );

CREATE TABLE no_answer(
    auto_id INTEGER NOT NULL AUTO_INCREMENT,
    uuid VARCHAR(37) NOT NULL,
    uuid_parent VARCHAR(37),
    fqdn VARCHAR(2048) NOT NULL,
    r_type VARCHAR(8) NOT NULL,
    reason VARCHAR(1024) NOT NULL,
    s_dt DATETIME,
    q_dt DATETIME,
    r_dt DATETIME,
    PRIMARY KEY (auto_id)
    );
