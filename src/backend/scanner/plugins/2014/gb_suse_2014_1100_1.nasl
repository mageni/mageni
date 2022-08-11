###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2014_1100_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Firefox openSUSE-SU-2014:1100-1 (Firefox)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850607");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-09-10 05:54:29 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2007-3089", "CVE-2007-3285", "CVE-2007-3656", "CVE-2007-3670",
                "CVE-2007-3734", "CVE-2007-3735", "CVE-2007-3736", "CVE-2007-3737",
                "CVE-2007-3738", "CVE-2008-0016", "CVE-2008-1233", "CVE-2008-1234",
                "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-3835",
                "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061",
                "CVE-2008-4062", "CVE-2008-4063", "CVE-2008-4064", "CVE-2008-4065",
                "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070",
                "CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017",
                "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024",
                "CVE-2008-5500", "CVE-2008-5501", "CVE-2008-5502", "CVE-2008-5503",
                "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510",
                "CVE-2008-5511", "CVE-2008-5512", "CVE-2009-0040", "CVE-2009-0771",
                "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0776",
                "CVE-2009-1571", "CVE-2009-3555", "CVE-2010-0159", "CVE-2010-0173",
                "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0182",
                "CVE-2010-0654", "CVE-2010-1121", "CVE-2010-1196", "CVE-2010-1199",
                "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203",
                "CVE-2010-1205", "CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213",
                "CVE-2010-1585", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754",
                "CVE-2010-2760", "CVE-2010-2762", "CVE-2010-2764", "CVE-2010-2765",
                "CVE-2010-2766", "CVE-2010-2767", "CVE-2010-2768", "CVE-2010-2769",
                "CVE-2010-3166", "CVE-2010-3167", "CVE-2010-3168", "CVE-2010-3169",
                "CVE-2010-3170", "CVE-2010-3173", "CVE-2010-3174", "CVE-2010-3175",
                "CVE-2010-3176", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180",
                "CVE-2010-3182", "CVE-2010-3183", "CVE-2010-3765", "CVE-2010-3768",
                "CVE-2010-3769", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778",
                "CVE-2011-0053", "CVE-2011-0061", "CVE-2011-0062", "CVE-2011-0069",
                "CVE-2011-0070", "CVE-2011-0072", "CVE-2011-0074", "CVE-2011-0075",
                "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081",
                "CVE-2011-0083", "CVE-2011-0084", "CVE-2011-0085", "CVE-2011-1187",
                "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2364", "CVE-2011-2365",
                "CVE-2011-2371", "CVE-2011-2372", "CVE-2011-2373", "CVE-2011-2374",
                "CVE-2011-2376", "CVE-2011-2377", "CVE-2011-2985", "CVE-2011-2986",
                "CVE-2011-2987", "CVE-2011-2988", "CVE-2011-2989", "CVE-2011-2991",
                "CVE-2011-2992", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3005",
                "CVE-2011-3026", "CVE-2011-3062", "CVE-2011-3101", "CVE-2011-3232",
                "CVE-2011-3648", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652",
                "CVE-2011-3654", "CVE-2011-3655", "CVE-2011-3658", "CVE-2011-3659",
                "CVE-2011-3660", "CVE-2011-3661", "CVE-2011-3663", "CVE-2012-0441",
                "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445",
                "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0451",
                "CVE-2012-0452", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457",
                "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461",
                "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464", "CVE-2012-0467",
                "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471",
                "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0475",
                "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479", "CVE-2012-0759",
                "CVE-2012-1937", "CVE-2012-1938", "CVE-2012-1940", "CVE-2012-1941",
                "CVE-2012-1944", "CVE-2012-1945", "CVE-2012-1946", "CVE-2012-1947",
                "CVE-2012-1948", "CVE-2012-1949", "CVE-2012-1951", "CVE-2012-1952",
                "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1956",
                "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1960",
                "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1967",
                "CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974",
                "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957",
                "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961",
                "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966",
                "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970",
                "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3975", "CVE-2012-3978",
                "CVE-2012-3980", "CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3984",
                "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3988", "CVE-2012-3989",
                "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993",
                "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180",
                "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184",
                "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188",
                "CVE-2012-4191", "CVE-2012-4192", "CVE-2012-4193", "CVE-2012-4194",
                "CVE-2012-4195", "CVE-2012-4196", "CVE-2012-4201", "CVE-2012-4202",
                "CVE-2012-4204", "CVE-2012-4205", "CVE-2012-4207", "CVE-2012-4208",
                "CVE-2012-4209", "CVE-2012-4212", "CVE-2012-4213", "CVE-2012-4214",
                "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-4217", "CVE-2012-4218",
                "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835",
                "CVE-2012-5836", "CVE-2012-5837", "CVE-2012-5838", "CVE-2012-5839",
                "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842", "CVE-2012-5843",
                "CVE-2013-0743", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746",
                "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750",
                "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755",
                "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0760",
                "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764",
                "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769",
                "CVE-2013-0770", "CVE-2013-0771", "CVE-2013-0773", "CVE-2013-0774",
                "CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782",
                "CVE-2013-0783", "CVE-2013-0787", "CVE-2013-0788", "CVE-2013-0789",
                "CVE-2013-0793", "CVE-2013-0795", "CVE-2013-0796", "CVE-2013-0800",
                "CVE-2013-0801", "CVE-2013-1669", "CVE-2013-1670", "CVE-2013-1674",
                "CVE-2013-1675", "CVE-2013-1676", "CVE-2013-1677", "CVE-2013-1678",
                "CVE-2013-1679", "CVE-2013-1680", "CVE-2013-1681", "CVE-2013-1682",
                "CVE-2013-1684", "CVE-2013-1685", "CVE-2013-1686", "CVE-2013-1687",
                "CVE-2013-1690", "CVE-2013-1692", "CVE-2013-1693", "CVE-2013-1694",
                "CVE-2013-1697", "CVE-2013-1701", "CVE-2013-1709", "CVE-2013-1710",
                "CVE-2013-1713", "CVE-2013-1714", "CVE-2013-1717", "CVE-2013-1718",
                "CVE-2013-1719", "CVE-2013-1720", "CVE-2013-1722", "CVE-2013-1723",
                "CVE-2013-1724", "CVE-2013-1725", "CVE-2013-1728", "CVE-2013-1730",
                "CVE-2013-1732", "CVE-2013-1735", "CVE-2013-1736", "CVE-2013-1737",
                "CVE-2013-1738", "CVE-2013-5590", "CVE-2013-5591", "CVE-2013-5592",
                "CVE-2013-5593", "CVE-2013-5595", "CVE-2013-5596", "CVE-2013-5597",
                "CVE-2013-5599", "CVE-2013-5600", "CVE-2013-5601", "CVE-2013-5602",
                "CVE-2013-5603", "CVE-2013-5604", "CVE-2013-5609", "CVE-2013-5610",
                "CVE-2013-5611", "CVE-2013-5612", "CVE-2013-5613", "CVE-2013-5614",
                "CVE-2013-5615", "CVE-2013-5616", "CVE-2013-5618", "CVE-2013-5619",
                "CVE-2013-6629", "CVE-2013-6630", "CVE-2013-6671", "CVE-2013-6672",
                "CVE-2013-6673", "CVE-2014-1477", "CVE-2014-1478", "CVE-2014-1479",
                "CVE-2014-1480", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1483",
                "CVE-2014-1484", "CVE-2014-1485", "CVE-2014-1486", "CVE-2014-1487",
                "CVE-2014-1488", "CVE-2014-1489", "CVE-2014-1490", "CVE-2014-1491",
                "CVE-2014-1492", "CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1497",
                "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1502",
                "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509",
                "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513",
                "CVE-2014-1514", "CVE-2014-1518", "CVE-2014-1519", "CVE-2014-1522",
                "CVE-2014-1523", "CVE-2014-1524", "CVE-2014-1525", "CVE-2014-1526",
                "CVE-2014-1528", "CVE-2014-1529", "CVE-2014-1530", "CVE-2014-1531",
                "CVE-2014-1532", "CVE-2014-1533", "CVE-2014-1534", "CVE-2014-1536",
                "CVE-2014-1537", "CVE-2014-1538", "CVE-2014-1539", "CVE-2014-1540",
                "CVE-2014-1541", "CVE-2014-1542", "CVE-2014-1543", "CVE-2014-1544",
                "CVE-2014-1545", "CVE-2014-1547", "CVE-2014-1548", "CVE-2014-1549",
                "CVE-2014-1550", "CVE-2014-1552", "CVE-2014-1553", "CVE-2014-1555",
                "CVE-2014-1556", "CVE-2014-1557", "CVE-2014-1558", "CVE-2014-1559",
                "CVE-2014-1560", "CVE-2014-1561", "CVE-2014-1562", "CVE-2014-1563",
                "CVE-2014-1564", "CVE-2014-1565", "CVE-2014-1567");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for Firefox openSUSE-SU-2014:1100-1 (Firefox)");
  script_tag(name:"insight", value:"This patch contains security updates for

  * mozilla-nss 3.16.4

  - The following 1024-bit root CA certificate was restored to allow more
  time to develop a better transition strategy for affected sites. It
  was removed in NSS 3.16.3, but discussion in the
  mozilla.dev.security.policy forum led to the decision to keep this
  root included longer in order to give website administrators more time
  to update their web servers.

  - CN = GTE CyberTrust Global Root

  * In NSS 3.16.3, the 1024-bit 'Entrust.net Secure Server Certification
  Authority' root CA certificate was removed. In NSS 3.16.4, a 2048-bit
  intermediate CA certificate has been included, without explicit trust.
  The intention is to mitigate the effects of the previous removal of
  the 1024-bit Entrust.net root certificate, because many public
  Internet sites still use the 'USERTrust Legacy Secure Server CA'
  intermediate certificate that is signed by the 1024-bit Entrust.net
  root certificate. The inclusion of the intermediate certificate is a
  temporary measure to allow those sites to function, by allowing them
  to find a trust path to another 2048-bit root CA certificate. The
  temporarily included intermediate certificate expires November 1, 2015.

  * Firefox 31.1esr Firefox is updated from 24esr to 31esr as maintenance
  for version 24 stopped");
  script_tag(name:"affected", value:"Firefox on openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Firefox'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"MozillaFirefox", rpm:"MozillaFirefox~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-branding-upstream", rpm:"MozillaFirefox-branding-upstream~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-buildsymbols", rpm:"MozillaFirefox-buildsymbols~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debuginfo", rpm:"MozillaFirefox-debuginfo~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-debugsource", rpm:"MozillaFirefox-debugsource~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-devel", rpm:"MozillaFirefox-devel~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-common", rpm:"MozillaFirefox-translations-common~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"MozillaFirefox-translations-other", rpm:"MozillaFirefox-translations-other~24.8.0~127.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3", rpm:"libfreebl3~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo", rpm:"libfreebl3-debuginfo~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3", rpm:"libsoftokn3~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo", rpm:"libsoftokn3-debuginfo~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss", rpm:"mozilla-nss~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs", rpm:"mozilla-nss-certs~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo", rpm:"mozilla-nss-certs-debuginfo~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo", rpm:"mozilla-nss-debuginfo~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debugsource", rpm:"mozilla-nss-debugsource~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-devel", rpm:"mozilla-nss-devel~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit", rpm:"mozilla-nss-sysinit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo", rpm:"mozilla-nss-sysinit-debuginfo~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools", rpm:"mozilla-nss-tools~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-tools-debuginfo", rpm:"mozilla-nss-tools-debuginfo~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-32bit", rpm:"libfreebl3-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo-32bit", rpm:"libfreebl3-debuginfo-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-32bit", rpm:"libsoftokn3-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo-32bit", rpm:"libsoftokn3-debuginfo-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-32bit", rpm:"mozilla-nss-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-32bit", rpm:"mozilla-nss-certs-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-32bit", rpm:"mozilla-nss-certs-debuginfo-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo-32bit", rpm:"mozilla-nss-debuginfo-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-32bit", rpm:"mozilla-nss-sysinit-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-32bit", rpm:"mozilla-nss-sysinit-debuginfo-32bit~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-debuginfo-x86", rpm:"libfreebl3-debuginfo-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libfreebl3-x86", rpm:"libfreebl3-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-debuginfo-x86", rpm:"libsoftokn3-debuginfo-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsoftokn3-x86", rpm:"libsoftokn3-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-debuginfo-x86", rpm:"mozilla-nss-certs-debuginfo-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-certs-x86", rpm:"mozilla-nss-certs-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-debuginfo-x86", rpm:"mozilla-nss-debuginfo-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-debuginfo-x86", rpm:"mozilla-nss-sysinit-debuginfo-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-sysinit-x86", rpm:"mozilla-nss-sysinit-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mozilla-nss-x86", rpm:"mozilla-nss-x86~3.16.4~94.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
