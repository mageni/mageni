###############################################################################
# OpenVAS Vulnerability Test
#
# Telepark.wiki Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.801068");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4087", "CVE-2009-4088", "CVE-2009-4089", "CVE-2009-4090");
  script_name("Telepark.wiki Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37391");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/54327");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/0911-exploits/Telepark-fixes-nov09-2.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_telepark_wiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("telepark.wiki/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct cross-site
  scripting attacks, bypass certain security restrictions, disclose sensitive
  information, and compromise a vulnerable system.");

  script_tag(name:"affected", value:"Telepark.wiki version prior to 2.4.25 on all platforms.");

  script_tag(name:"insight", value:"The following issues exist:

  - An input appended to the URL after 'index.php' is not properly sanitised
  before being returned to the user.

  - An improper authentication verification error in '/ajax/deletePage.php'
  can be exploited to delete pages without any user credentials.

  - An improper authentication verification error in '/ajax/deleteComment.php'
  can be exploited to delete comments without any user credentials.

  - An input passed via various parameters to multiple scripts is not properly verified
  before being used to include files.

  - An error in the '/ajax/addComment.php' script not properly verifying uploaded files.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Telepark.wiki version 2.4.25 or later.");

  script_tag(name:"summary", value:"This host is running Telepark.wiki and is prone to multiple
  vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

twikiPort = get_http_port(default:80);

twikiVer = get_kb_item("www/" + twikiPort + "/Telepark.wiki");
twikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:twikiVer);
if(twikiVer[1] != NULL)
{
  if(version_is_less(version:twikiVer[1], test_version:"2.4.25")){
    security_message(port:twikiPort, data:"The target host was found to be vulnerable.");
    exit(0);
  }
}

exit(99);
