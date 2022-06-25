###############################################################################
# OpenVAS Vulnerability Test
#
# YABSoft AIHS Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801092");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-17 08:14:37 +0100 (Thu, 17 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4266", "CVE-2009-1032");
  script_bugtraq_id(37233, 34176);
  script_name("YABSoft AIHS Cross Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/34366");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49316");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54582");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/10336");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_yabsoft_aihs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("yabsoft/aihs/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to conduct cross-site
  scripting and SQL injection attacks.");

  script_tag(name:"affected", value:"YABSoft AIHS version 2.3 and prior on all running platform.");

  script_tag(name:"insight", value:"The flaws are due to:

  - Input passed to the 'gal' parameter in 'gallery_list.php' is not properly
  sanitised before being used in SQL queries.

  - Input passed to the 'text' parameter in 'search.php' is not properly
  sanitised before being returned to the user.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running YABSoft AIHS and is prone to Cross-Site Scripting
  and SQL Injection vulnerabilities");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

aihsPort = get_http_port(default:80);

aihsVer = get_kb_item("www/" + aihsPort + "/YABSoft/AIHS");
if(!aihsVer)
  exit(0);

aihsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:aihsVer);
if(!safe_checks() && aihsVer[2] != NULL)
{
  request = http_get(item:aihsVer[2] + "/search.php?text=%3Cscript%3E"+
          "alert(123456)%3C/script%3E&dosearch=Search", port:aihsPort);
  response = http_send_recv(port:aihsPort, data:request);

  if(response =~ "HTTP/1\.. 200" && "<script>alert(123456)</script>" >< response)
  {
    security_message(aihsPort);
    exit(0);
  }
}

if(aihsVer[1] != NULL)
{
  if(version_is_less_equal(version:aihsVer[1], test_version:"2.3")){
    security_message(aihsPort);
  }
}
