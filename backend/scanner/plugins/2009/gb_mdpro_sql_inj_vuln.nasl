###############################################################################
# OpenVAS Vulnerability Test
#
# MDPro Surveys Module SQL Injection Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800919");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-08-07 07:29:21 +0200 (Fri, 07 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2618");
  script_bugtraq_id(35495);
  script_name("MDPro Surveys Module SQL Injection Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9021");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/51385");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mdpro_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("mdpro/detected");

  script_tag(name:"impact", value:"This flaw can be exploited via malicious SQL commands to modify
  or delete information in the back-end database.");

  script_tag(name:"affected", value:"MDPro version 1.083.x");

  script_tag(name:"insight", value:"The Surveys module fails to validate the user supplied data
  passed into the 'pollID' parameter before using it in an SQL query.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is installed with MDPro and is prone to SQL Injection
  vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

mdproPort = get_http_port(default:80);

mdproVer = get_kb_item("www/" + mdproPort + "/MDPro");
mdproVer = eregmatch(pattern:"^(.+) under (/.*)$", string:mdproVer);

if(mdproVer[1] =~ "^1\.083"){
  security_message(mdproPort);
}
