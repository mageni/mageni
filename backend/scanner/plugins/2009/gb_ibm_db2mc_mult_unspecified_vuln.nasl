###############################################################################
# OpenVAS Vulnerability Test
#
# DB2 Monitoring Console Multiple Unspecified Security Bypass Vulnerabilities
#
# Authors:
# Antu Sanadi<santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800691");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-7130", "CVE-2008-7131");
  script_bugtraq_id(28253);
  script_name("DB2 Monitoring Console Multiple Unspecified Security Bypass Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29367");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/384393.php");
  script_xref(name:"URL", value:"http://sourceforge.net/forum/forum.php?forum_id=797405");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_db2mc_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ibm/db2mc/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass certain
  security restrictions or potentially compromise a vulnerable system.");

  script_tag(name:"affected", value:"DB2 Monitoring Console Version 2.2.24 and prior.");

  script_tag(name:"insight", value:"- An unspecified error can be exploited to upload files to the web
  server hosting the application.

  - An unspecified error can be exploited to gain access to the database
  that a user is currently connected to by tricking the user to access malicious link.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to DB2 Monitoring Console Version 2.2.25 or later.");

  script_tag(name:"summary", value:"The host is running IBM DMC and is prone to multiple
  Unspecified Security Bypass Vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

dmcPort = get_http_port(default:80);

dmcVer = get_kb_item("www/" + dmcPort + "/IBM/DB2MC");
if(!dmcVer)
  exit(0);

dmcVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dmcVer);
if(dmcVer[1] != NULL)
{
  if(version_is_less_equal(version:dmcVer[1], test_version:"2.2.24")){
    security_message(dmcPort);
  }
}
