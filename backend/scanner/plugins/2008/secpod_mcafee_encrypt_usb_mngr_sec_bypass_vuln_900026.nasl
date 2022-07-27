##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mcafee_encrypt_usb_mngr_sec_bypass_vuln_900026.nasl 14310 2019-03-19 10:27:27Z cfischer $
#
# McAfee Encrypted USB Manager Remote Security Bypass Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900026");
  script_version("$Revision: 14310 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:27:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3605");
  script_bugtraq_id(30630);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Brute force attacks");
  script_name("McAfee Encrypted USB Manager Remote Security Bypass Vulnerability");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://secunia.com/advisories/31433/");
  script_xref(name:"URL", value:"http://www.mcafee.com/apps/downloads/security_updates/hotfixes.asp?region=us&segment=enterprise");

  script_tag(name:"affected", value:"McAfee Encrypted USB Manager 3.1.0.0 on Windows (All).");
  script_tag(name:"insight", value:"The issue is caused when the password policy, 'Re-use Threshold' is set to
  non-zero value.");

  script_tag(name:"summary", value:"The host is running McAfee Encrypted USB Manager, which is prone
  to sensitive information disclosure vulnerability.");

  script_tag(name:"solution", value:"Apply Service Pack 1 or upgrade to latest McAfee Encrypted USB Manager.");

  script_tag(name:"impact", value:"Remote exploitation could lead an attacker towards password
  guessing.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\McAfee\ACCESSEnterpriseManager")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  mcAfee = registry_get_sz(key:key + entry, item:"DisplayName");

  if(mcAfee && "McAfee Encrypted USB Manager" >< mcAfee) {

    if(egrep(pattern:"McAfee Encrypted USB Manager 3\.1(\.0)?$", string:mcAfee)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);