###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visual Studio Insecure Library Loading Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902255");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-29 09:26:02 +0200 (Wed, 29 Sep 2010)");
  script_cve_id("CVE-2010-3190");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Visual Studio Insecure Library Loading Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41212");
  script_xref(name:"URL", value:"http://www.corelan.be:8800/index.php/2010/08/25/dll-hijacking-kb-2269637-the-unofficial-list/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_mandatory_keys("Microsoft/VisualStudio/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow the attackers to execute
  arbitrary code and conduct DLL hijacking attacks.");
  script_tag(name:"affected", value:"Microsoft Visual Studio");

  script_tag(name:"insight", value:"The flaw is due to 'ATL MFC Trace Tool'(AtlTraceTool8.exe)
  loading libraries in an insecure manner. This can be exploited to load
  arbitrary libraries by tricking a user into opening a TRC file located on a remote WebDAV or SMB share.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is installed with Microsoft Visual Studio and is prone
  to insecure library loading vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.900285.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS11-025.mspx");
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-025.nasl