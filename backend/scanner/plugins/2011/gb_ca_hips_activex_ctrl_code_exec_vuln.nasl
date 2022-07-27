###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ca_hips_activex_ctrl_code_exec_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# CA Host-Based Intrusion Prevention System 'XMLSecDB' ActiveX Control Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801858");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-10 13:33:28 +0100 (Thu, 10 Mar 2011)");
  script_cve_id("CVE-2011-1036");
  script_bugtraq_id(46539);
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_name("CA Host-Based Intrusion Prevention System 'XMLSecDB' ActiveX Control Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43377/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65632");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-093");
  script_xref(name:"URL", value:"https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID={53A608DF-BFDB-4AB3-A98F-E4BB6BC7A2F4}");
  script_xref(name:"URL", value:"https://support.ca.com/irj/portal/anonymous/SolutionResults?aparNo=RO26950&actionID=4");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_ca_mult_prdts_detect_win.nasl");
  script_mandatory_keys("CA/Multiple_Products/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
code in the context of the logged-in user. Failed exploits result in
denial-of-service conditions.");
  script_tag(name:"affected", value:"CA Internet Security Suite (ISS) 2010
CA Internet Security Suite (ISS) 2011
CA Host-Based Intrusion Prevention System (HIPS) r8.1");
  script_tag(name:"insight", value:"The flaw is caused by a design error in the XMLSecDB ActiveX
control installed with the HIPSEngine component, which could allow attackers
to create arbitrary files on a vulnerable system by tricking a user into
visiting a web page which calls the 'SetXml()' and 'Save()' methods.");
  script_tag(name:"summary", value:"This host is installed with CA Host-Based Intrusion Prevention
System(HIPS) and is prone to a remote code-execution vulnerability.");
  script_tag(name:"solution", value:"Vendor has released a patch to fix this issue, refer below link
for patch information.

*****
NOTE : Ignore this warning, if above mentioned patch is already applied.
*****

CA Internet Security Suite (ISS):");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

if(ver = get_kb_item("CA/HIPS/Server/Win/Ver"))
{
  if(version_is_less(version:ver, test_version:"8.1.0.88"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

## CA Internet Security Suite (ISS)
if((hipsVer = get_kb_item("CA/HIPS/Engine/Win/Ver")) &&
   (issVer = get_kb_item("CA/ISS/Win/Ver")))
{
  ## CA Internet Security Suite (ISS) 2010:
  if(version_in_range(version:issVer, test_version:"6.0", test_version2:"6.0.0.285") &&
     version_is_less_equal(version:hipsVer, test_version:"1.6.384")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }

  ## CA Internet Security Suite (ISS) 2011:
  else if(version_in_range(version:issVer, test_version:"7.0", test_version2:"7.0.0.115") &&
     version_is_less_equal(version:hipsVer, test_version:"1.6.418")) {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
