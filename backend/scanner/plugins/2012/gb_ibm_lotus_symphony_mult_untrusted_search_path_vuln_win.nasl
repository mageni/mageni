###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_lotus_symphony_mult_untrusted_search_path_vuln_win.nasl 12634 2018-12-04 07:26:26Z cfischer $
#
# IBM Lotus Symphony Multiple Untrusted Search Path Vulnerabilities (Windows)
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

CPE = "cpe:/a:ibm:lotus_symphony";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802963");
  script_version("$Revision: 12634 $");
  script_cve_id("CVE-2010-5204");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 08:26:26 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2012-09-17 15:01:39 +0530 (Mon, 17 Sep 2012)");
  script_name("IBM Lotus Symphony Multiple Untrusted Search Path Vulnerabilities (Windows)");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41400");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2264107");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Sep/220");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/advisory/2269637#EGF");
  script_xref(name:"URL", value:"http://core.yehg.net/lab/pr0js/advisories/dll_hijacking/%5Bibm_lotus_symphony%5D_3-beta-4_insecure_dll_hijacking");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_lotus_symphony_detect_win.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("IBM/Lotus/Symphony/Win/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code on the target system.");

  script_tag(name:"affected", value:"IBM Lotus Symphony version 1.3.0 Revision 20090908.0900");

  script_tag(name:"insight", value:"The flaw is due to the way it loads dynamic-link libraries
  (e.g. eclipse_1114.dll and emser645mi.dll) in an insecure manner. This can
  be exploited to load arbitrary libraries by tricking a user into e.g. opening
  a ODT, STW, or SXW file located on a remote WebDAV or SMB share.");

  script_tag(name:"summary", value:"This host is installed with IBM Lotus Symphony and is prone to
  multiple untrusted search path vulnerabilities.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

version = get_app_version(cpe:CPE);
if(!version){
  exit(0);
}

key = "SYSTEM\CurrentControlSet\Control\Session Manager";
if(registry_key_exists(key:key))
{
  val = registry_get_dword(key:key, item:"CWDIllegalInDLLSearch");
  if(val){
    exit(0);
  }
}

if(version_is_equal(version:version, test_version:"1.3.09251")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
