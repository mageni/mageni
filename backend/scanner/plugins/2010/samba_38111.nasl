###############################################################################
# OpenVAS Vulnerability Test
# $Id: samba_38111.nasl 10398 2018-07-04 12:11:48Z cfischer $
#
# Samba Symlink Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100488");
  script_version("$Revision: 10398 $");
  script_cve_id("CVE-2010-0926");
  script_bugtraq_id(38111);
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 14:11:48 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2010-02-08 23:29:56 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_name("Samba Symlink Directory Traversal Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Remote file access");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38111");
  script_xref(name:"URL", value:"http://www.samba.org/samba/news/symlink_attack.html");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-02/0100.html");
  script_xref(name:"URL", value:"http://www.samba.org");
  script_xref(name:"URL", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2010-February/072927.html");
  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2010-0926.html");

  script_tag(name:"summary", value:"Samba is prone to a directory-traversal vulnerability because the
  application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Exploits would allow an attacker to access files outside of the Samba
  user's root directory to obtain sensitive information and perform other attacks.");

  script_tag(name:"affected", value:"Samba versions before 3.3.11, 3.4.x before 3.4.6, and 3.5.x before 3.5.0rc3.");

  script_tag(name:"solution", value:"The vendor commented on the issue stating that it stems from an
  insecure default configuration. The Samba team advises administrators to set 'wide links = no' in
  the '[global]' section of 'smb.conf' and then restart the service to correct misconfigured services.

  Please see the references for more information.");

  script_tag(name:"insight", value:"To exploit this issue, attackers require authenticated access to a
  writable share. Note that this issue may be exploited through a writable share accessible by guest accounts.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if( version_is_less( version:vers, test_version:"3.3.11" ) ||
    version_in_range( version:vers, test_version:"3.4", test_version2:"3.4.5" ) ||
    version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.0rc2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.3.11/3.4.6/3.5.0rc3", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
