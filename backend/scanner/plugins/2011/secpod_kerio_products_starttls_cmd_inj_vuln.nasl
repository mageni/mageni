###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kerio_products_starttls_cmd_inj_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Kerio Products 'STARTTLS' Plaintext Command Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901194");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-1506");
  script_bugtraq_id(46767);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Kerio Products 'STARTTLS' Plaintext Command Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_kerio_mailserver_detect.nasl");
  script_mandatory_keys("KerioMailServer/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43678");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0610");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  commands in the context of the user running the application.");

  script_tag(name:"affected", value:"Kerio MailServer versions 6.x Kerio Connect version 7.1.4
  build 2985");

  script_tag(name:"insight", value:"This flaw is caused by an error within the 'STARTTLS'
  implementation where the switch from plaintext to TLS is implemented below the
  application's I/O buffering layer, which could allow attackers to inject commands
  during the plaintext phase of the protocol via man-in-the-middle attacks.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Kerio Mail Server/Connect and is prone to
  plaintext command injection vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( vers = get_app_version( cpe:"cpe:/a:kerio:kerio_mailserver", nofork:TRUE, version_regex:"^6\." ) ) {
  if( version_in_range( version:vers, test_version:"6.0", test_version2:"6.7.3.patch1" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

if( vers = get_app_version( cpe:"cpe:/a:kerio:connect", nofork:TRUE, version_regex:"^7\." ) ) {
  if( version_is_equal( version:vers, test_version:"7.1.4" ) ) {
    report = report_fixed_ver( installed_version:vers, fixed_version:"WillNotFix" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );