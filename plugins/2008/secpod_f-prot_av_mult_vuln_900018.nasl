##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_f-prot_av_mult_vuln_900018.nasl 14310 2019-03-19 10:27:27Z cfischer $
#
# F-PROT Antivirus Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.900018");
  script_version("$Revision: 14310 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:27:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
  script_cve_id("CVE-2008-3244");
  script_bugtraq_id(30253, 30258);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("F-PROT Antivirus Multiple Vulnerabilities");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://www.f-prot.com/download/ReleaseNotesWindows.txt");

  script_tag(name:"summary", value:"The remote host is installed with F-PROT Antivirus, which is
  prone multiple denial of service vulnerabilities.");

  script_tag(name:"insight", value:"The issues are due to,

  - input validation error while processing the nb_dir field of
  CHM file's header.

  - improper handling of specially crafted UPX-compressed files,
  Microsoft Office files, and ASPack-compressed files.");

  script_tag(name:"affected", value:"F-Prot Antivirus for Windows prior to 6.0.9.0 on Windows (All).");

  script_tag(name:"solution", value:"Upgrade to latest F-PROT Antivirus or later.");

  script_tag(name:"impact", value:"Remote attackers can easily crash the engine/service via
  specially crafted files.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\FRISK Software\F-PROT Antivirus for Windows")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

foreach entry(registry_enum_keys(key:key)) {

  fprotName = registry_get_sz(item:"DisplayName", key:key + entry);

  if(fprotName && "F-PROT Antivirus for Windows" >< fprotName) {

    fprotVer = registry_get_sz(item:"DisplayVersion", key:key + entry);

    if(fprotVer && egrep(pattern:"^([0-5]\..*|6\.0\.[0-8](\..*)?)$", string:fprotVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
    exit(99);
  }
}

exit(0);