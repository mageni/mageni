###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer 'toStaticHTML()' Cross Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.902246");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-09-23 08:13:58 +0200 (Thu, 23 Sep 2010)");
  script_cve_id("CVE-2010-3324");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Microsoft Internet Explorer 'toStaticHTML()' Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass the
  cross-site scripting (XSS) protection mechanism and conduct XSS attacks.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 8.x to 8.0.6001.18702");

  script_tag(name:"insight", value:"The flaw is due to error in the 'toStaticHTML()' which is not
  properly handling the 'Cascading Style Sheets (CSS)'.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is installed with Internet Explorer and is prone to
  cross site scripting vulnerability.

  This NVT has been replaced by OID:1.3.6.1.4.1.25623.1.0.901162.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.wooyun.org/bug.php?action=view&id=189");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/fulldisclosure/2010-08/0179.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-071.mspx");

  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms10-071.nasl.