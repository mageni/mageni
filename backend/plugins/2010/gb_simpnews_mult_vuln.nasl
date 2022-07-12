##############################################################################
# OpenVAS Vulnerability Test
#
# SimpNews Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801391");
  script_version("2019-05-14T08:13:05+0000");
  script_tag(name:"last_modification", value:"2019-05-14 08:13:05 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-2858", "CVE-2010-2859");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SimpNews Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40501");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/60244");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1007-exploits/simpnews-xss.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/512271/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simpnews_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("simpnews/detected");

  script_tag(name:"insight", value:"The flaws are exists due to:

  - An error 'news.php', allow remote attackers to inject arbitrary web scripts
  via the 'layout' and 'sortorder' parameters.

  - An error in 'news.php' allows remote attackers to obtain sensitive
  information via an invalid lang parameter, which reveals the installation
  path in an error message.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the SimpNews version 2.48 or later.");

  script_tag(name:"summary", value:"This host is running SimpNews and is prone to multiple
  vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary web
  scripts and to obtain sensitive information.");

  script_tag(name:"affected", value:"SimpNews Version 2.47.03 and prior.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

snPort = get_http_port(default:80);

ver = get_kb_item(string("www/", snPort, "/SimpNews"));
if(!ver)
  exit(0);

simpnewsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(isnull(simpnewsVer[1]))
  exit(0);

if(version_is_less_equal(version:simpnewsVer[1], test_version:"2.47.03")){
  security_message(port:snPort);
}
