###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ida_pro_mult_vuln.nasl 14117 2019-03-12 14:02:42Z cfischer $
#
# Hex-Rays IDA Pro Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.901189");
  script_version("$Revision: 14117 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 15:02:42 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-1049", "CVE-2011-1050", "CVE-2011-1051",
                "CVE-2011-1052", "CVE-2011-1053", "CVE-2011-1054");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Hex-Rays IDA Pro Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43190");
  script_xref(name:"URL", value:"https://www.hex-rays.com/vulnfix.shtml");
  script_xref(name:"URL", value:"https://www.hex-rays.com/machofix.shtml");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0357");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("secpod_ida_pro_detect.nasl");
  script_mandatory_keys("IDA/Pro/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code or
  cause a denial of service.");
  script_tag(name:"affected", value:"Hex-Rays IDA Pro versions 5.7 and 6.0");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - A buffer overflow error in the Mach-O input file loader allows user-assisted
    remote attackers to cause a denial of service.

  - An unspecified error related to 'conversion of string encodings' and
    'inconsistencies in the handling of UTF8 sequences by the user interface'.

  - An integer overflow error in the COFF/EPOC/EXPLOAD input file loaders.

  - An Integer overflow error in the PSX/GEOS input file loaders.

  - An unspecified error in the Mach-O input file loader allows user-assisted
    remote attackers to cause a denial of service.

  - An unspecified error in the PEF input file loader.");
  script_tag(name:"summary", value:"This host is installed with Hex-Rays IDA Pro and is prone to
  multiple vulnerabilities.");
  script_tag(name:"solution", value:"Apply the patch from the referenced vendor URL.

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");

idaVer = get_kb_item("IDA/Pro/Ver");

if(idaVer =~ "^6\.0\..*" || idaVer =~ "^5\.7\..*"){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
