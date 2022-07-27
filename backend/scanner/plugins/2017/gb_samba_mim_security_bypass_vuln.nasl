###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_samba_mim_security_bypass_vuln.nasl 11901 2018-10-15 08:47:18Z mmartin $
#
# Samba Man in the Middle Security Bypass Vulnerability (Heimdal)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811522");
  script_version("$Revision: 11901 $");
  script_cve_id("CVE-2017-11103");
  script_bugtraq_id(99551);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-15 10:47:18 +0200 (Mon, 15 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-13 12:28:31 +0530 (Thu, 13 Jul 2017)");
  script_name("Samba Man in the Middle Security Bypass Vulnerability (Heimdal)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2017-11103.html");

  script_tag(name:"summary", value:"This host is running Samba and is prone
  to a MITM authentication validation bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in function
  '_krb5_extract_ticket' where the KDC-REP service name must be obtained from
  encrypted version stored in 'enc_part' instead of the unencrypted version
  stored in 'ticket'. Use of the unecrypted version provides an opportunity
  for successful server impersonation and other attacks.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  a MITM attacker to impersonate a trusted server and thus gain elevated access
  to the domain by returning malicious replication or authorization data.");

  script_tag(name:"affected", value:"All versions of Samba from 4.0.0 before
  4.6.6 or 4.5.12 or 4.4.15.

  Note: All versions of Samba from 4.0.0 onwards using embedded Heimdal Kerberos.
  Samba binaries built against MIT Kerberos are not vulnerable.");

  script_tag(name:"solution", value:"Upgrade to Samba 4.6.6 or 4.5.12 or 4.4.15
  or later or apply the patch from below.");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security");
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

if(vers =~ "^4\."){
  if(version_is_less(version:vers, test_version:"4.4.15")){
    fix = "4.4.15";
  }

  else if(vers =~ "^4\.5" && version_is_less(version:vers, test_version:"4.5.12")){
    fix = "4.5.12";
  }

  else if(vers =~ "^4\.6" && version_is_less(version:vers, test_version:"4.6.6")){
    fix = "4.6.6";
  }
}

if(fix){
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:loc );
  security_message( data:report, port:port);
  exit(0);
}

exit(99);
