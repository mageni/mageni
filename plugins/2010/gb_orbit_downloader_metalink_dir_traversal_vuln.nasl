###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orbit_downloader_metalink_dir_traversal_vuln.nasl 11553 2018-09-22 14:22:01Z cfischer $
#
# Orbit Downloader metalink 'name' Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801214");
  script_version("$Revision: 11553 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-22 16:22:01 +0200 (Sat, 22 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2104");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Orbit Downloader metalink 'name' Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/511348/100/100/threaded");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2010-73/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/39527");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_orbit_downloader_detect.nasl");
  script_mandatory_keys("OrbitDownloader/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to download files to
directories outside of the intended download directory via directory traversal
attacks.");
  script_tag(name:"affected", value:"Orbit Downloader Version 3.0.0.4 and 3.0.0.5");
  script_tag(name:"insight", value:"The flaw is due to an error in the handling of metalink files.
The 'name' attribute of a 'file' element in a metalink file is not properly
sanitised.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is installed with Orbit Downloader and is prone to
directory traversal vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

ver = get_kb_item("OrbitDownloader/Ver");

if(ver){
  if(version_is_equal(version:ver, test_version:"3.0.0.4") ||
     version_is_equal(version:ver, test_version:"3.0.0.5") ){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
