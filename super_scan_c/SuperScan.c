//
// Created by mac on 2022/1/4.
//
// python 模块


//https://docs.python.org/3.8/c-api/arg.html#strings-and-buffers
#define PY_SSIZE_T_CLEAN

#include "Python.h"
#include "stub-pcap.h"
#include "rawsock.h"
#include "massip-addr.h"
#include "stack-arpv4.h"
#include "siphash24.h"
#include "templ-pkt.h"


/* 获取系统默认网卡 */
static PyObject *py_GetDefaultNic(PyObject *self, PyObject *args) {
    int err;
    char ifname2[256] = {0};
    err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
    if (err || ifname2[0] == '\0') {
        Py_RETURN_NONE;
    }

    return Py_BuildValue("s", ifname2);
}

/* pcap 环境初始化 */
static PyObject *py_PcapInit(PyObject *self, PyObject *args) {
    pcap_init();
    Py_RETURN_NONE;
}

/* 网卡初始化，设置通过pcap打开，再设置参数，主要是网卡mac地址等 */
static PyObject *py_rawSocketInit(PyObject *self, PyObject *args) {
    const char *ifname = NULL;
    // 默认不是offline模式，如果是的话，则is_offline为1, offline模式其实就是打开pcap文件
    char errbuf[256] = "pcap";
    pcap_t *pcap_tmp = NULL;
    // 存放pcap打开指针
    PyObject *adapter = NULL;
    PyArg_ParseTuple(args, "s", &ifname);
    if (memcmp(ifname, "file:", 5) == 0) {
        pcap_tmp = PCAP.open_offline(ifname + 5, errbuf);
    } else {
        // 这时候我们调用libpcap打开网卡接口
        // https://codeantenna.com/a/1k63tUKYmb
        pcap_tmp = PCAP.create(ifname, errbuf);
        if (pcap_tmp == NULL) {
            // 为了兼容1。0版本之前的pcap
            // https://blog.csdn.net/zhuzitop/article/details/116535924
            pcap_tmp = PCAP.open_live(
                    ifname,           /* interface name */
                    1024,                  /* max packet size */
                    8,                      /* promiscuous mode */
                    1000,                   /* read timeout in milliseconds */
                    errbuf);
            if (pcap_tmp == NULL) {
                PyObject *error = PyErr_NewException("OpenedException", NULL, NULL);
                if (strstr(errbuf, "perm")) {
                    PyErr_SetString(error, "permission denied");
                    Py_RETURN_NONE;
                } else {
                    PyErr_SetString(error, "can't open adapter");
                    Py_RETURN_NONE;
                }
            }
        } else {
            // 设置最大捕获包长度 65536
            // https://hokkaitao.github.io/libcap-05
            int err = 0;
            err = PCAP.set_snaplen(pcap_tmp, 1024);
            if (err) {
                memcmp(errbuf, "set_snaplen", sizeof("set_snaplen"));
                goto pcap_error;
            }

            // 设置混杂模式
            err = PCAP.set_promisc(pcap_tmp, 8);
            if (err) {
                memcmp(errbuf, "set_promisc", sizeof("set_promisc"));
                goto pcap_error;
            }
            // 设置捕获操作的持续操作
            err = PCAP.set_timeout(pcap_tmp, 1000);
            if (err) {
                memcmp(errbuf, "set_timeout", sizeof("set_timeout"));
                goto pcap_error;
            }

            err = PCAP.set_immediate_mode(pcap_tmp, 1);
            if (err) {
                memcmp(errbuf, "set_immediate_mode", sizeof("set_immediate_mode"));
                goto pcap_error;
            }

            /* If errors happen, they aren't likely to happen above, but will
             * happen where when they are applied */
            err = PCAP.activate(pcap_tmp);
            switch (err) {
                case 0:
                    /* drop down below */
                    break;
                case PCAP_ERROR_PERM_DENIED:
                    memcmp(errbuf, "permission denied, need to sudo or run as root or something",
                           sizeof("permission denied, need to sudo or run as root or something"));
                    goto pcap_error;
                default:
                    if (err < 0) {
                        memcmp(errbuf, "can't activited interface", sizeof("can't activited interface"));
                        goto pcap_error;
                    }
            }

        }
    }
    //https://www.tcpdump.org/linktypes.html 所有链路类型
    PyObject *pcap = PyCapsule_New(pcap_tmp, "pcap_t", NULL);
    /***************************************************************************
    * Configure the socket to not capture transmitted packets. This is needed
    * because we transmit packets at a rate of millions per second, which will
    * overwhelm the receive thread.
    */
    PCAP.setdirection(pcap_tmp, PCAP_D_IN);
    return pcap;
    pcap_error:
    if (pcap_tmp != NULL) {
        PCAP.close(pcap_tmp);
        pcap_tmp = NULL;
    }
    PyObject *error = PyErr_NewException("OpenedException", NULL, NULL);
    PyErr_SetString(error, errbuf);
    return NULL;
}


/* 根据网卡名字，获取相对应的mac地址 */
static PyObject *py_rawsock_get_adapter_mac(PyObject *self, PyObject *args) {
    const char *ifname = NULL;
    PyArg_ParseTuple(args, "s", &ifname);
    unsigned char mac[6] = {0};
    rawsock_get_adapter_mac(ifname, mac);
    PyObject *mac_py = Py_BuildValue("y#", mac, sizeof(mac));
    return mac_py;
}

/* 根据网卡名字，获取接口的ip地址 */
static PyObject *py_rawsock_get_adapter_ip(PyObject *self, PyObject *args) {
    const char *ifname = NULL;
    PyArg_ParseTuple(args, "s", &ifname);
    unsigned ip = rawsock_get_adapter_ip(ifname);
    PyObject *ip_py = Py_BuildValue("I", ip);
    return ip_py;
}

/* 根据网卡名字，获取接口的网关地址 */
static PyObject *py_rawsock_get_default_gateway(PyObject *self, PyObject *args) {
    const char *ifname = NULL;
    PyArg_ParseTuple(args, "s", &ifname);
    unsigned gw;
    rawsock_get_default_gateway(ifname, &gw);
    PyObject *gw_py = Py_BuildValue("I", gw);
    return gw_py;
}

/* 在指定的网卡上，对指定的ip地址做arp查询 */
static PyObject *py_arp_resolv(PyObject *self, PyObject *args) {
    PyObject *adapter;
    unsigned int ipme = 0;
    unsigned int gw = 0;
    Py_buffer pyBuffer;
    PyArg_ParseTuple(args, "OIIy*", &adapter, &ipme, &gw, &pyBuffer);
    macaddress_t mymac;
    memcpy(mymac.addr, pyBuffer.buf, pyBuffer.len);
    PyBuffer_Release(&pyBuffer);
    macaddress_t yourMac;
    stack_arp_resolve(adapter, ipme, mymac, gw, &yourMac);
    Py_ssize_t size = sizeof(yourMac.addr);
    PyObject *mac_py = Py_BuildValue("y#", yourMac.addr, size);
    return mac_py;
}

/* siphash24 算法 */
static PyObject *py_siphash24(PyObject *self, PyObject *args) {
    unsigned ip_me = 0;
    unsigned port_me = 0;
    unsigned ip_them = 0;
    unsigned port_them = 0;
    uint64_t entropy = 0;
    PyArg_ParseTuple(args, "IIIIK", &ip_me, &port_me, &ip_them, &port_them, &entropy);
    unsigned data[4];
    uint64_t x[2];

    x[0] = entropy;
    x[1] = entropy;

    data[0] = ip_them;
    data[1] = port_them;
    data[2] = ip_me;
    data[3] = port_me;
    uint64_t sip_hash = siphash24(data, sizeof(data), x);
    PyObject *sip_hash_py = Py_BuildValue("K", sip_hash);
    return sip_hash_py;
}

/* 初始化tcp udp的报文 返回一个指针 */
static PyObject *py_template_packet_init(PyObject *self, PyObject *args) {
    // 本机网卡mac地址
    macaddress_t my_mac;
    int my_mac_len = 0;
    // 路由器mac地址
    macaddress_t rt_mac;
    // 目前来讲，扫描ipv6没有太多意义，所以ipv6的网关mac与ipv4一样，但是为了后期升级考虑
    // 还是暂时留空，就不删除
    // 链路类型
    int link_type = 1;
    //随机种子 也就是seed
    uint64_t entropy = 0;
    Py_buffer my_mac_buf;
    Py_buffer rt_mac_buf;
    struct TemplateSet *template_set = (struct TemplateSet *) malloc(sizeof(struct TemplateSet));
    // 函数参数 sourcemac rtmac, linktype, seed
    PyArg_ParseTuple(args, "y*y*iK", &my_mac_buf, &rt_mac_buf, &link_type, &entropy);
    memcpy(my_mac.addr, my_mac_buf.buf, my_mac_buf.len);
    memcpy(rt_mac.addr, rt_mac_buf.buf, rt_mac_buf.len);
    PyBuffer_Release(&my_mac_buf);
    PyBuffer_Release(&rt_mac_buf);
    template_packet_init(template_set, my_mac, rt_mac, rt_mac, link_type, entropy);
    PyObject *px_template = PyCapsule_New(template_set, "struct TemplateSet", NULL);
    return px_template;
}

/* 设置报文模版的ttl */
static PyObject *py_template_set_ttl(PyObject *self, PyObject *args) {

    PyObject *px_template;
    unsigned TTL = 0;
    // 函数参数 px_template ttl
    PyArg_ParseTuple(args, "OI", &px_template, &TTL);
    struct TemplateSet *template_set = PyCapsule_GetPointer(px_template, "struct TemplateSet");
    template_set_ttl(template_set, TTL);
    Py_RETURN_NONE;
}

static PyObject *py_rawsock_send_ipv4(PyObject *self, PyObject *args) {

    PyObject *px_template_py;
    PyObject *pcap_py;

    unsigned ip_me = 0;
    unsigned port_me = 0;
    unsigned ip_them = 0;
    unsigned port_them = 0;
    uint64_t seqno = 0;

    PyArg_ParseTuple(args, "OOIIIIK", &px_template_py, &pcap_py, &ip_me, &port_me, &ip_them, &port_them, &seqno);
    struct TemplateSet *tmplset = PyCapsule_GetPointer(px_template_py, "struct TemplateSet");
    pcap_t *pcap = PyCapsule_GetPointer(pcap_py, "pcap_t");


    unsigned char px[2048];
    size_t packet_length;

    /*
     * Construct the destination packet
     */
    template_set_target_ipv4(tmplset, ip_them, port_them, ip_me, port_me, (unsigned) seqno,
                             px, sizeof(px), &packet_length);

    /*
     * Send it
     */
    rawsock_send_packet(pcap, px, (unsigned) packet_length);
    Py_RETURN_NONE;
}

static PyObject *py_rawsock_recv_packet(PyObject *self, PyObject *args) {
    /*
     * 该函数负责从pcap打开的接口中，接收捕获的报文。如果出现异常，则返回none，需要调用方自行判断
     */
    const unsigned char *px;
    PyObject *pcap_py;

    PyArg_ParseTuple(args, "O", &pcap_py);
    pcap_t *pcap = PyCapsule_GetPointer(pcap_py, "pcap_t");

    struct pcap_pkthdr *hdr;

    int error = PCAP.next_ex(pcap, &hdr, &px);
    if (error == 0) {
        Py_RETURN_NONE;
    }

    PyObject *packet_response = Py_BuildValue("y#", px, hdr->len);
    return packet_response;

}

static PyObject *py_PcapClose(PyObject *self, PyObject *args) {
    /*
     * 关闭pcap接口，如果多次打开会报错的
     */
    PyObject *pcap_py;
    PyArg_ParseTuple(args, "O", &pcap_py);
    pcap_t *pcap = PyCapsule_GetPointer(pcap_py, "pcap_t");
    PCAP.close(pcap);
    Py_RETURN_NONE;
}


/* Module method table */
static PyMethodDef SuperScanMethods[] = {
        {"get_default_nic",      py_GetDefaultNic,               METH_VARARGS, "get default nic name"},
        {"pcap_init",            py_PcapInit,                    METH_VARARGS, "initialize the pcap runtime"},
        {"pcap_close",           py_PcapClose,                   METH_VARARGS, "close the pcap"},
        {"raw_socket_init",      py_rawSocketInit,               METH_VARARGS, "initialize the raw socket in nic"},
        {"get_adapter_mac",      py_rawsock_get_adapter_mac,     METH_VARARGS, "get adapter mac"},
        {"get_adapter_ip",       py_rawsock_get_adapter_ip,      METH_VARARGS, "get adapter ip"},
        {"get_default_gateway",  py_rawsock_get_default_gateway, METH_VARARGS, "get adapter default gateway"},
        {"arp_resolv",           py_arp_resolv,                  METH_VARARGS, "arp resolv"},
        {"siphash24",            py_siphash24,                   METH_VARARGS, "arp resolv"},
        {"template_packet_init", py_template_packet_init,        METH_VARARGS, "template_packet_init"},
        {"template_set_ttl",     py_template_set_ttl,            METH_VARARGS, "set ttl"},
        {"rawsock_send_ipv4",    py_rawsock_send_ipv4,           METH_VARARGS, "send packet"},
        {"rawsock_recv_packet",  py_rawsock_recv_packet,         METH_VARARGS, "recv package"},
        {NULL,                   NULL,                           0,            NULL}
};

/* Module structure */
static struct PyModuleDef SuperScanmodule = {
        PyModuleDef_HEAD_INIT,

        "SuperScan",           /* name of module */
        "super masscan",  /* Doc string (may be NULL) */
        -1,                 /* Size of per-interpreter state or -1 */
        SuperScanMethods       /* Method table */
};

/* Module initialization function */
PyMODINIT_FUNC
PyInit_SuperScan_C(void) {
    return PyModule_Create(&SuperScanmodule);
}
