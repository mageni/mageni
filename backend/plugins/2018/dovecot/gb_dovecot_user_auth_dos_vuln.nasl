###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dovecot_user_auth_dos_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Dovecot User Authentication Denial of Service Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113215");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-06-26 14:11:32 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2669");

  script_name("Dovecot User Authentication Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_dovecot_consolidation.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Dovecot is prone to a Denial of Service vulnerability within the user authentication.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"When 'dict' passdb and userdb were used for user authentication, the username sent by
  the IMAP/POP3 client is sent through var_expand() to perform %variable expansion.
  Sending specially crafed %variable fields can result in excessive memory usage
  causing the process to crash (and restart), or excessive CPU usage
  causing all authentications to hang.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to temporarily deny
  every user to access the application.");
  script_tag(name:"affected", value:"Dovecot versions 2.2.26 through 2.2.28.");
  script_tag(name:"solution", value:"Update to version 2.2.29.");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2017/04/11/1");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2017-2669");

  exit(0);
}

CPE = "cpe:/a:dovecot:dovecot";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! version = get_app_version( cpe: CPE, nofork: TRUE ) ) exit( 0 );

if( version_in_range( version: version, test_version: "2.2.26", test_version2: "2.2.28" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.2.29" );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
