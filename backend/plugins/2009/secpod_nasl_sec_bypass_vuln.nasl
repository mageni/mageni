###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSL DSA_do_verify() Security Bypass Vulnerability in NASL
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900190");
  script_version("2019-05-03T10:20:18+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:20:18 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0125");
  script_bugtraq_id(33151);
  script_name("OpenSSL DSA_do_verify() Security Bypass Vulnerability in NASL");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=479655");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2009/01/12/4");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=511517");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_nasl_detect_lin.nasl");
  script_mandatory_keys("NASL/Linux/Ver");

  script_tag(name:"summary", value:"The host is running NASL and is prone to Security Bypass
  vulnerability.

  NOTE: the upstream vendor has disputed this issue, stating 'while we do misuse this function (this is a bug), it has absolutely no security ramification.'.");

  script_tag(name:"solution", value:"No solution provided as no fix is required.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);