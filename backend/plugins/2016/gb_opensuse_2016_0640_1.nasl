###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0640_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for libopenssl0_9_8 openSUSE-SU-2016:0640-1 (libopenssl0_9_8)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851223");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-03-04 06:42:46 +0100 (Fri, 04 Mar 2016)");
  script_cve_id("CVE-2013-0166", "CVE-2013-0169", "CVE-2014-0076", "CVE-2014-0195",
                "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2014-3505",
                "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3510",
                "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568", "CVE-2014-3569",
                "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275",
                "CVE-2015-0204", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287",
                "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0293", "CVE-2015-1788",
                "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792",
                "CVE-2015-3195", "CVE-2015-3197", "CVE-2016-0797", "CVE-2016-0799",
                "CVE-2016-0800");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for libopenssl0_9_8 openSUSE-SU-2016:0640-1 (libopenssl0_9_8)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libopenssl0_9_8'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for libopenssl0_9_8 fixes the following issues:

  - CVE-2016-0800 aka the 'DROWN' attack (bsc#968046): OpenSSL was
  vulnerable to a cross-protocol attack that could lead to decryption of
  TLS sessions by using a server supporting SSLv2 and EXPORT cipher suites
  as a Bleichenbacher RSA padding oracle.

  This update changes the openssl library to:

  * Disable SSLv2 protocol support by default.

  This can be overridden by setting the environment variable
  'OPENSSL_ALLOW_SSL2' or by using SSL_CTX_clear_options using the
  SSL_OP_NO_SSLv2 flag.

  Note that various services and clients had already disabled SSL
  protocol 2 by default previously.

  * Disable all weak EXPORT ciphers by default. These can be re-enabled if
  required by old legacy software using the environment variable
  'OPENSSL_ALLOW_EXPORT'.

  - CVE-2016-0797 (bnc#968048): The BN_hex2bn() and BN_dec2bn() functions
  had a bug that could result in an attempt to de-reference a NULL pointer
  leading to crashes. This could have security consequences if these
  functions were ever called by user applications with large untrusted
  hex/decimal data. Also, internal usage of these functions in OpenSSL
  uses data from config files or application command line arguments. If
  user developed applications generated config file data based on
  untrusted data, then this could have had security consequences as well.

  - CVE-2016-0799 (bnc#968374) On many 64 bit systems, the internal fmtstr()
  and doapr_outch() functions could miscalculate the length of a string
  and attempt to access out-of-bounds memory locations. These problems
  could have enabled attacks where large amounts of untrusted data is
  passed to the BIO_*printf functions. If applications use these functions
  in this way then they could have been vulnerable. OpenSSL itself uses
  these functions when printing out human-readable dumps of ASN.1 data.
  Therefore applications that print this data could have been vulnerable
  if the data is from untrusted sources. OpenSSL command line applications
  could also have been vulnerable when they print out ASN.1 data, or if
  untrusted data is passed as command line arguments. Libssl is not
  considered directly vulnerable.


  - The package was updated to 0.9.8zh:

  * fixes many security vulnerabilities (not separately listed):
  CVE-2015-3195, CVE-2015-1788, CVE-2015-1789, CVE-2015-1790,
  CVE-2015-1792, CVE-2015-1791, CVE-2015-0286, CVE-2015-0287,
  CVE-2015-0289, CVE-2015-0293, CVE-2015-0209, CVE-2015-0288,
  CVE-2014-3571, CVE-2014-3569, CVE-2014-3572, CVE-2015-0204,
  CVE-2014-8 ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"libopenssl0_9_8 on openSUSE Leap 42.1, openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8zh~9.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo", rpm:"libopenssl0_9_8-debuginfo~0.9.8zh~9.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debugsource", rpm:"libopenssl0_9_8-debugsource~0.9.8zh~9.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8zh~9.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libopenssl0_9_8-debuginfo-32bit", rpm:"libopenssl0_9_8-debuginfo-32bit~0.9.8zh~9.3.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
