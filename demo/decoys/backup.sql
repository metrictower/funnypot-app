-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)
--
-- Host: localhost    Database: app_prod
-- ------------------------------------------------------
-- Server version	8.0.36

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `role` varchar(32) NOT NULL DEFAULT 'user',
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` VALUES (1,'admin@app.local','$2y$10$Qb1Xg7mJ0aVw9pKcR3nZ7uHlF2sD8yTq6eW4rB0iN1oP5cM3xL9C','admin');
INSERT INTO `users` VALUES (2,'j.reyes@app.local','$2y$10$7nKpR2vB4mZ0wQ8sT1yUdeXcL6oH3gF9aJ5rN0iP2kM4bV7xD1sO','user');
INSERT INTO `users` VALUES (3,'support@app.local','$2y$10$3fH9kL2mN8pQ4rS6tU0vBeW1xY7zC5aD9gJ0iK3lM6nO2pR8sT4u','user');

DROP TABLE IF EXISTS `api_keys`;
CREATE TABLE `api_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(64) NOT NULL,
  `secret` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `api_keys` VALUES (1,'AWS_ACCESS_KEY_ID','AKIAIOSFODNN7EXAMPLE');
INSERT INTO `api_keys` VALUES (2,'AWS_SECRET_ACCESS_KEY','wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
INSERT INTO `api_keys` VALUES (3,'STRIPE_SECRET_KEY','sk_live_51HxExampleExampleExampleExampleExample00');
INSERT INTO `api_keys` VALUES (4,'SMTP_PASSWORD','SG.ExampleExampleExampleEx.ExampleExampleExampleExampleExampleEx');

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
-- Dump completed
