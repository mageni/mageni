###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ecava_integraxor_mult_xss_vuln_win.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Ecava IntegraXor Multiple Cross-Site Scripting Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802314");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2958");
  script_bugtraq_id(48958);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Ecava IntegraXor Multiple Cross-Site Scripting Vulnerabilities (Windows)");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68896");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-147-02.pdf");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.
  This may allow an attacker to steal cookie-based authentications and launch
  further attacks.");
  script_tag(name:"affected", value:"Ecava IntegraXor versions prior to 3.60 (Build 4080).");
  script_tag(name:"insight", value:"The flaws are caused by improper validation of user-supplied input passed via
  unspecified vectors, which allows attackers to execute arbitrary HTML and
  script code on the web server.");
  script_tag(name:"solution", value:"Upgrade to the Ecava IntegraXor version 3.60 (Build 4080) or later.");
  script_tag(name:"summary", value:"This host is installed with Ecava IntegraXor and is prone to cross
  site scripting vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.ecava.com/index.htm");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)) {
    exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  ecavaigName = registry_get_sz(key:key + item, item:"DisplayName");

  if("IntegraXor" >< ecavaigName)
  {
    ecavaigVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(ecavaigVer != NULL)
    {
      if(version_is_less(version:ecavaigVer, test_version:"3.60.4080"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }
  }
}
