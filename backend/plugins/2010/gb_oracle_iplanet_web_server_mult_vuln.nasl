###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_iplanet_web_server_mult_vuln.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Oracle iPlanet Web Server Multiple Unspecified Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801607");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-22 15:51:55 +0200 (Fri, 22 Oct 2010)");
  script_bugtraq_id(43984);
  script_cve_id("CVE-2010-3544", "CVE-2010-3545");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Oracle iPlanet Web Server Multiple Unspecified vulnerabilities");

  script_xref(name:"URL", value:"http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpuoct2010-175626.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_sun_java_sys_web_serv_detect.nasl");
  script_mandatory_keys("java_system_web_server/installed");
  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to affect confidentiality,
  integrity and availability via unknown vectors related to Administration.");
  script_tag(name:"affected", value:"Oracle iPlanet Web Server(Sun Java System Web Server) 7.0");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors, which allow remote attackers
  to affect confidentiality, integrity and availability via unknown vectors
  related to Administration.");
  script_tag(name:"summary", value:"The host is running Oracle iPlanet Web Server and is prone to
  multiple unspecified vulnerabilities.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Apply the patch  *****
  NOTE: Ignore this warning if above mentioned patch is already applied.
  *****");
  script_xref(name:"URL", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-79-1215353.1-1");
  exit(0);
}


include("version_func.inc");

jswsVer = get_kb_item("Sun/JavaSysWebServ/Ver");
jswsPort = get_kb_item("Sun/JavaSysWebServ/Port");

if(jswsVer != NULL)
{
  if(version_is_equal(version:jswsVer, test_version:"7.0")) {
    security_message(jswsPort);
  }
}
