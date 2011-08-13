-- phpMyAdmin SQL Dump
-- version 2.11.11.3
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Aug 13, 2011 at 02:01 PM
-- Server version: 5.0.77
-- PHP Version: 5.1.6

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `receiptomatic`
--

-- --------------------------------------------------------

--
-- Table structure for table `activations`
--

CREATE TABLE IF NOT EXISTS `activations` (
  `user` varchar(255) NOT NULL,
  `akey` varchar(64) NOT NULL,
  `expires` int(11) NOT NULL,
  UNIQUE KEY `user` (`user`),
  KEY `akey` (`akey`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `approved`
--

CREATE TABLE IF NOT EXISTS `approved` (
  `id` varchar(64) NOT NULL,
  `uid` int(10) unsigned NOT NULL,
  `username` varchar(255) NOT NULL,
  `timestamp` int(10) unsigned NOT NULL,
  `status` smallint(5) unsigned NOT NULL,
  `reason` varchar(255) NOT NULL,
  UNIQUE KEY `id` (`id`),
  KEY `timestamp` (`timestamp`),
  KEY `uid` (`uid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `field_names`
--

CREATE TABLE IF NOT EXISTS `field_names` (
  `uid` int(10) unsigned NOT NULL,
  `username` varchar(255) NOT NULL,
  `receipt_date` varchar(255) NOT NULL,
  `department` varchar(255) NOT NULL,
  `employee_number` varchar(255) NOT NULL,
  `reason` varchar(255) NOT NULL,
  `po_num` varchar(255) NOT NULL,
  `cost_codes` varchar(255) NOT NULL,
  `account_codes` varchar(255) NOT NULL,
  `supplier_name` varchar(255) NOT NULL,
  `supplier_town` varchar(255) NOT NULL,
  `vat_number` varchar(255) NOT NULL,
  `gross_amount` varchar(255) NOT NULL,
  `net_amount` varchar(255) NOT NULL,
  `vat_amount` varchar(255) NOT NULL,
  `vat_rate` varchar(255) NOT NULL,
  `currency` varchar(255) NOT NULL,
  `payment_method` varchar(255) NOT NULL,
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `uid` (`uid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `images`
--

CREATE TABLE IF NOT EXISTS `images` (
  `id` varchar(64) NOT NULL,
  `uid` int(10) unsigned NOT NULL,
  `username` varchar(255) NOT NULL,
  `timestamp` int(10) unsigned NOT NULL,
  `path` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `processed` tinyint(4) unsigned NOT NULL default '0',
  `approved` tinyint(3) unsigned NOT NULL default '1',
  UNIQUE KEY `id` (`id`),
  KEY `processed` (`processed`),
  KEY `who` (`username`),
  KEY `approved` (`approved`),
  KEY `uid` (`uid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `passwd`
--

CREATE TABLE IF NOT EXISTS `passwd` (
  `uid` int(10) unsigned NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(106) NOT NULL,
  `name` varchar(255) NOT NULL,
  `capabilities` smallint(5) unsigned NOT NULL default '0',
  `enabled` tinyint(1) NOT NULL default '0',
  `activated` tinyint(1) NOT NULL default '0',
  `d_reason` varchar(255) NOT NULL,
  UNIQUE KEY `uid` (`uid`),
  UNIQUE KEY `username` (`username`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `tags`
--

CREATE TABLE IF NOT EXISTS `tags` (
  `id` varchar(64) NOT NULL,
  `uid` int(10) unsigned NOT NULL,
  `username` varchar(255) NOT NULL,
  `timestamp` int(10) unsigned NOT NULL,
  `employee_number` varchar(255) NOT NULL,
  `department` varchar(50) NOT NULL,
  `po_num` varchar(30) NOT NULL,
  `cost_codes` varchar(255) NOT NULL,
  `account_codes` varchar(255) NOT NULL,
  `supplier_town` varchar(255) NOT NULL,
  `supplier_name` varchar(255) NOT NULL,
  `currency` varchar(3) NOT NULL,
  `gross_amount` decimal(12,2) NOT NULL,
  `vat_amount` decimal(12,2) NOT NULL,
  `net_amount` decimal(12,2) NOT NULL,
  `vat_rate` decimal(5,2) NOT NULL,
  `vat_number` varchar(20) NOT NULL,
  `receipt_date` int(10) unsigned NOT NULL,
  `reason` varchar(255) NOT NULL,
  `payment_method` varchar(6) NOT NULL,
  UNIQUE KEY `id` (`id`),
  KEY `timestamp` (`timestamp`),
  KEY `payment_method` (`payment_method`),
  KEY `uid` (`uid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `utmp`
--

CREATE TABLE IF NOT EXISTS `utmp` (
  `login_at` double(16,6) NOT NULL,
  `uid` int(10) unsigned NOT NULL,
  `username` varchar(255) NOT NULL,
  `ip` varchar(39) NOT NULL,
  `hostname` varchar(255) NOT NULL,
  `sid` bigint(20) unsigned NOT NULL,
  UNIQUE KEY `sid` (`sid`),
  KEY `uid` (`uid`),
  KEY `login_at` (`login_at`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;
