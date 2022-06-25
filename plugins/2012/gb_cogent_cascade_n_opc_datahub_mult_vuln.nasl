###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cogent_cascade_n_opc_datahub_mult_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# Cogent OPC DataHub and Cascade DataHub XSS and CRLF Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802565");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-0310", "CVE-2012-0309");
  script_bugtraq_id(51375);
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-01-20 18:01:09 +0530 (Fri, 20 Jan 2012)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_name("Cogent OPC DataHub and Cascade DataHub XSS and CRLF Vulnerabilities");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN12983784/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN63249231/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000001.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2012/JVNDB-2012-000002.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaws are due to unspecified errors in the applications, allows
  remote attackers to inject arbitrary web script or HTML via unspecified vectors.");
  script_tag(name:"solution", value:"Upgrade to the OPC DataHub version 7.2 or later.

  Upgrade to the Cascade DataHub version 7.2 or later.");
  script_tag(name:"summary", value:"This host is installed with OPC DataHub or Cascade DataHub and is
  prone to cross site scripting and CRLF vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.");
  script_tag(name:"affected", value:"OPC DataHub version 6.4.20 and prior
  Cascade DataHub version 6.4.20 and prior");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.cogentdatahub.com/index.html");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

function version_check(ver)
{
  if(version_is_less_equal(version:ver, test_version:"6.4.20"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

if(registry_key_exists(key:"SOFTWARE\Cogent\OPC DataHub"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OPC DataHub";
  if(registry_key_exists(key:key))
  {
    dataVer = registry_get_sz(key:key, item:"DisplayVersion");
    if(dataVer){
      version_check(ver:dataVer);
    }
  }
}


if(registry_key_exists(key:"SOFTWARE\Cogent\Cascade DataHub"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Cascade DataHub";
  if(!(registry_key_exists(key:key))){
    exit(0);
  }

  dataVer = registry_get_sz(key:key, item:"DisplayVersion");
  if(!dataVer){
    exit(0);
  }
  version_check(ver:dataVer);
}
