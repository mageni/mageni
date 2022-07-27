###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dropbear_ssh_crlf_injection_vuln.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# Dropbear SSH CRLF Injection Vulnerability
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:matt_johnston:dropbear_ssh_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807740");
  script_version("$Revision: 14181 $");
  script_cve_id("CVE-2016-3116");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-04-06 16:24:50 +0530 (Wed, 06 Apr 2016)");
  script_name("Dropbear SSH CRLF Injection Vulnerability");

  script_tag(name:"summary", value:"This host is installed with Dropbear SSH
  and is prone to crlf injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to invalid processing
  of 'X11' forwarding input.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote authenticated users to inject commands to xauth..");

  script_tag(name:"affected", value:"Dropbear SSH before 2016.72");

  script_tag(name:"solution", value:"Upgrade to Dropbear SSH version 2016.72 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/CHANGES");
  script_xref(name:"URL", value:"https://github.com/tintinweb/pub/tree/master/pocs/cve-2016-3116");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_dropbear_ssh_detect.nasl");
  script_mandatory_keys("dropbear/installed");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!sshPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!sshVer = get_app_version(cpe:CPE, port:sshPort)){
  exit(0);
}

if(version_is_less(version:sshVer, test_version:"2016.72"))
{
  report = report_fixed_ver(installed_version:sshVer, fixed_version:'2016.72');
  security_message(port:sshPort, data:report);
  exit(0);
}
