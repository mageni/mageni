# OpenVAS Vulnerability Test
# $Id: smbcl_gnutls_CB-A08-0079.nasl 13901 2019-02-27 09:33:17Z cfischer $
# Description: GnuTLS < 2.2.4 vulnerability (Windows)
#
# Authors:
# Carsten Koch-Mauthe <c.koch-mauthe at dn-systems.de>
# Modified to implement through 'smb_nt.inc'
#- By Nikita MR <rnikita@secpod.com> on 2009-09-17
#
# Copyright:
# Copyright (C) 2008 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:gnu:gnutls";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.90027");
  script_version("$Revision: 13901 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-27 10:33:17 +0100 (Wed, 27 Feb 2019) $");
  script_tag(name:"creation_date", value:"2008-09-06 20:50:27 +0200 (Sat, 06 Sep 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
  script_name("GnuTLS < 2.2.4 vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gnutls_detect_win.nasl");
  script_mandatory_keys("gnutls/detected");

  script_tag(name:"solution", value:"All GnuTLS users should upgrade to the latest version.");

  script_tag(name:"summary", value:"The remote host is probably affected by the vulnerabilities described in
  CVE-2008-1948, CVE-2008-1949, CVE-2008-1950");

  script_tag(name:"impact", value:"CVE-2008-1948

  The _gnutls_server_name_recv_params function in lib/ext_server_name.c
  in libgnutls in gnutls-serv in GnuTLS before 2.2.4 does not properly
  calculate the number of Server Names in a TLS 1.0 Client Hello
  message during extension handling, which allows remote attackers
  to cause a denial of service (crash) or possibly execute arbitrary
  code via a zero value for the length of Server Names, which leads
  to a buffer overflow in session resumption data in the
  pack_security_parameters function, aka GNUTLS-SA-2008-1-1.

  CVE-2008-1949

  The _gnutls_recv_client_kx_message function in lib/gnutls_kx.c
  in libgnutls in gnutls-serv in GnuTLS before 2.2.4 continues to
  process Client Hello messages within a TLS message after one has
  already been processed, which allows remote attackers to cause a
  denial of service (NULL dereference and crash) via a TLS message
  containing multiple Client Hello messages, aka GNUTLS-SA-2008-1-2.

  CVE 2008-1950

  Integer signedness error in the _gnutls_ciphertext2compressed
  function in lib/gnutls_cipher.c in libgnutls in GnuTLS before 2.2.4
  allows remote attackers to cause a denial of service (buffer over-read
  and crash) via a certain integer value in the Random field in an
  encrypted Client Hello message within a TLS record with an invalid
  Record Length, which leads to an invalid cipher padding length,
  aka GNUTLS-SA-2008-1-3.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"2.2.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.4", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );