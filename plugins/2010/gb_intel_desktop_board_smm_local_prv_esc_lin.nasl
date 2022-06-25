###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_desktop_board_smm_local_prv_esc_lin.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# Intel Desktop Boards SMM Local Privilege Escalation Vulnerability (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800164");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-11 16:37:59 +0100 (Thu, 11 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0560");
  script_name("Intel Desktop Boards SMM Local Privilege Escalation Vulnerability (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_desktop_board_bios_info_detect_lin.nasl");
  script_mandatory_keys("DesktopBoards/BIOS/Ver", "DesktopBoards/BIOS/Vendor",
                        "DesktopBoards/BaseBoard/ProdName");
  script_require_keys("DesktopBoards/BaseBoard/Manufacturer");
  script_tag(name:"impact", value:"Successful exploitation lets the local users to bypass certain security
  restrictions and gain elevated privileges.");
  script_tag(name:"affected", value:"Intel Desktop Board DB, DG, DH, DP, and DQ Series");
  script_tag(name:"insight", value:"An unspecified error exists in System Management Mode (SMM) implementation
  in Intel Desktop Boards, which could allow software running administrative
  (ring 0) privilege to change code running in SMM.");
  script_tag(name:"solution", value:"Upgrade the BIOS.");
  script_tag(name:"summary", value:"This host has Intel Desktop Boards running which is prone to
  Local Privilege Escalation Vulnerability.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38413");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0271");
  script_xref(name:"URL", value:"http://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00022&languageid=en-fr");
  exit(0);
}


include("version_func.inc");

bios_ver = get_kb_item("DesktopBoards/BIOS/Ver");
bios_vendor = get_kb_item("DesktopBoards/BIOS/Vendor");
base_board_manu = get_kb_item("DesktopBoards/BaseBoard/Manufacturer");
base_board_prod_name = get_kb_item("DesktopBoards/BaseBoard/ProdName");

if(bios_ver == NULL || bios_vendor == NULL || base_board_prod_name == NULL ){
  exit(0);
}

if(!(egrep(pattern:"Intel",string:bios_vendor) &&
     egrep(pattern:"Intel",string:base_board_manu))){
  exit(0);
}

## All affected products
aff_prods = ["DQ43AP", "DQ45CB", "DQ45EK", "DQ35JO", "DQ35MP", "DP55KG",
             "DP55SB", "DP55WG", "DP55WB", "DQ57TM", "DH55TC", "DH55HC",
             "DG41KR", "DB43LD", "DG41MJ", "DG41RQ", "DG41TY"];

## All fixed product versions, kept in order as affected products
fix_prod_ver = ["APQ4310H.86A.0031", "CBQ4510H.86A.0109", "CBQ4510H.86A.0109",
                "JOQ3510J.86A.1126", "JOQ3510J.86A.1126", "KGIBX10J.86A.4236",
                "KGIBX10J.86A.4236", "KGIBX10J.86A.4236", "WBIBX10J.86A.0181",
                "TMIBX10H.86A.0025", "TCIBX10H.86A.0028", "TCIBX10H.86A.0028",
                "KRG4110H.86A.0029", "LDB4310H.86A.0035", "MJG4110H.86A.0006",
                "RQG4110H.86A.0013", "TYG4110H.86A.0037"];

aff_prods_len = max_index(aff_prods);

for(i=0; i < aff_prods_len ; i++)
{
  if(base_board_prod_name == aff_prods[i])
  {
    ## Extract Proper Version for matching
    intel_bios_ver = split(bios_ver, sep: '.');
    intel_bios_ver = intel_bios_ver[0] + intel_bios_ver[1]
                     + (intel_bios_ver[2] - ".");

    ## with respect to perticular product i.e aff_prods
    if(version_is_less(version:intel_bios_ver, test_version:fix_prod_ver[i])){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
