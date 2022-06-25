###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortiweb_FG-IR-14-018.nasl 14184 2019-03-14 13:29:04Z cfischer $
#
# FortiOS: Multiple Vulnerabilities in OpenSSL
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/a:fortinet:fortiweb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105209");
  script_cve_id("CVE-2014-0224", "CVE-2014-0221", "CVE-2014-0195");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 14184 $");

  script_name("FortiOS: Multiple Vulnerabilities in OpenSSL");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-14-018");

  script_tag(name:"impact", value:"CVE-2014-0224 may allow an attacker with a privileged network position (man-in-the-middle) to decrypt SSL encrypted
communications.

CVE-2014-0221 may allow an attacker to crash a DTLS client with an invalid handshake.

CVE-2014-0195 can result in a buffer overrun attack by sending invalid DTLS fragments to an OpenSSL DTLS client or server.

CVE-2014-0198 and CVE-2010-5298 may allow an attacker to cause a denial of service under certain conditions, when SSL_MODE_RELEASE_BUFFERS
is enabled.

CVE-2014-3470 may allow an attacker to trigger a denial of service in SSL clients when anonymous ECDH ciphersuites are enabled. This issue
does not affect Fortinet products.

CVE-2014-0076 can be used to discover ECDSA nonces on multi-user systems by exploiting timing attacks in CPU L3 caches. This does not apply
to Fortinet products.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to FortiWeb 5.3.1 or higher.");

  script_tag(name:"summary", value:"Multiple Vulnerabilities in OpenSSL");

  script_tag(name:"affected", value:"FortiWeb < 5.3.1");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:29:04 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-02-11 12:17:13 +0100 (Wed, 11 Feb 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_fortiweb_version.nasl");
  script_mandatory_keys("fortiweb/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

version = get_app_version( cpe:CPE );
if( ! version )
  version = get_kb_item("fortiweb/version");

if( ! version ) exit( 0 );

fix = "5.3.1";

if( version_is_less( version:version, test_version:fix ) )
{
  model = get_kb_item("fortiweb/model");
  if( ! isnull( model ) ) report = 'Model:             ' + model + '\n';
  report += 'Installed Version: ' + version + '\nFixed Version:     ' + fix + '\n';
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );