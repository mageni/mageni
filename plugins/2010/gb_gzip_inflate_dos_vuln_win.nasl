###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gzip_inflate_dos_vuln_win.nasl 14331 2019-03-19 14:03:05Z jschulte $
#
# GZip 'huft_build()' in 'inflate.c' Input Validation Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800452");
  script_version("$Revision: 14331 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:03:05 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2624");
  script_bugtraq_id(37888);
  script_name("GZip 'huft_build()' in 'inflate.c' Input Validation Vulnerability (Windows)");

  script_xref(name:"URL", value:"http://www.gzip.org/index-f.html#sources");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38132");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0185");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=514711");
  script_xref(name:"URL", value:"http://git.savannah.gnu.org/cgit/gzip.git/commit/?id=39a362ae9d9b007473381dba5032f4dfc1744cf2");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_gzip_detect_win.nasl");
  script_mandatory_keys("GZip/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could result in Denial of service (application
  crash or infinite loop) or possibly execute arbitrary code via a crafted
  archive.");
  script_tag(name:"affected", value:"GZip version prior to 1.3.13 on Windows");
  script_tag(name:"insight", value:"The flaw is due to error in 'huft_build()' function in 'inflate.c', creates
  a hufts table that is too small.");
  script_tag(name:"summary", value:"This host is installed with GZip and is prone to Input Validation
  Vulnerability");
  script_tag(name:"solution", value:"Apply the patch or Upgrade to GZip version 1.3.13

  *****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
  *****");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

gzipVer = get_kb_item("GZip/Win/Ver");
if(!gzipVer){
  exit(0);
}

if(version_is_less(version:gzipVer, test_version:"1.3.13")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
