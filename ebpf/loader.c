/*
 * - loader.c: Final version with selectable modes (dynamic/fixed)
 */
#define _POSIX_C_SOURCE 199309L
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/pkt_cls.h>
#include <signal.h>

// --- Default Parameters ---
#define DEFAULT_MIN_RATE_PPS 1000
#define DEFAULT_MAX_RATE_PPS 100000
#define DEFAULT_MAX_PROBABILITY 50
#define UPDATE_INTERVAL_SEC 1

// Define our operating modes
enum operating_mode {
    MODE_DYNAMIC,
    MODE_FIXED,
};

struct state {
    __u64 packet_count;
    __u64 dropped_count;
    __u32 drop_probability;
};

static int ifindex_g;

// (cleanup and get_time_ns functions remain the same)
static void cleanup(int sig) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g,
                        .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
    exit(0);
}

static __u64 get_time_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: sudo %s <interface> --mode <dynamic|fixed> [options]\n\n"
        "Modes:\n"
        "  dynamic                Dynamically adjust probability based on traffic load.\n"
        "  fixed                  Set a fixed drop probability.\n\n"
        "Options for 'dynamic' mode:\n"
        "  --max-prob <int>         Maximum drop probability (0-100, default: %d)\n"
        "  --min-rate <int>         PPS rate to start dropping (default: %d)\n"
        "  --max-rate <int>         PPS rate to reach max probability (default: %d)\n\n"
        "Options for 'fixed' mode:\n"
        "  --prob <int>             Fixed drop probability (0-100, required for fixed mode)\n\n"
        "General options:\n"
        "  -h, --help               Display this help message\n"
        , prog, DEFAULT_MAX_PROBABILITY, DEFAULT_MIN_RATE_PPS, DEFAULT_MAX_RATE_PPS);
}

int main(int argc, char **argv) {
    struct bpf_object *bpf_obj;
    struct bpf_program *ing_prog, *eg_prog;
    int map_fd;
    __u64 last_time_ns = 0, last_packet_count = 0;

    // --- New variables for mode selection ---
    enum operating_mode mode = -1; // -1 indicates mode not set
    long prob = -1; // -1 indicates probability not set

    // --- Variables for dynamic mode ---
    long max_prob = DEFAULT_MAX_PROBABILITY;
    long min_rate = DEFAULT_MIN_RATE_PPS;
    long max_rate = DEFAULT_MAX_RATE_PPS;
    int opt;

    // --- Add new options to getopt_long ---
    static struct option long_options[] = {
        {"mode",     required_argument, 0,  0 }, // Use index 0 for mode
        {"prob",     required_argument, 0, 'p'},
        {"max-prob", required_argument, 0, 'P'},
        {"min-rate", required_argument, 0, 'm'},
        {"max-rate", required_argument, 0, 'M'},
        {"help",     no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "p:P:m:M:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 0: // This case is for long options that don't have a short option char
                if (strcmp("mode", long_options[option_index].name) == 0) {
                    if (strcmp("dynamic", optarg) == 0) {
                        mode = MODE_DYNAMIC;
                    } else if (strcmp("fixed", optarg) == 0) {
                        mode = MODE_FIXED;
                    } else {
                        fprintf(stderr, "Error: Invalid mode '%s'. Use 'dynamic' or 'fixed'.\n", optarg);
                        usage(argv[0]);
                        return 1;
                    }
                }
                break;
            case 'p': prob = atol(optarg); break;
            case 'P': max_prob = atol(optarg); break;
            case 'm': min_rate = atol(optarg); break;
            case 'M': max_rate = atol(optarg); break;
            case 'h': default: usage(argv[0]); return 1;
        }
    }

    // --- Validate arguments based on selected mode ---
    if (mode == -1) {
        fprintf(stderr, "Error: Operating mode is required. Use --mode <dynamic|fixed>\n");
        usage(argv[0]);
        return 1;
    }
    if (mode == MODE_FIXED && prob == -1) {
        fprintf(stderr, "Error: --prob is required for fixed mode.\n");
        usage(argv[0]);
        return 1;
    }
     // --- Validate arguments based on selected mode (Corrected Logic) ---
     if (mode == MODE_FIXED) {
         if (prob < 0 || prob > 100) {
             fprintf(stderr, "Error: for fixed mode, --prob must be between 0 and 100.\n");
             return 1;
         }
     } else { // MODE_DYNAMIC
         if (max_prob < 0 || max_prob > 100) {
             fprintf(stderr, "Error: for dynamic mode, --max-prob must be between 0 and       100.\n");
             return 1;
         }  
      }
      
    if (optind >= argc) {
        fprintf(stderr, "Error: Interface name is required.\n");
        usage(argv[0]);
        return 1;
    }
    const char *ifname = argv[optind];

    // (BPF Loading and Attaching part remains unchanged...)
    ifindex_g = if_nametoindex(ifname);
    if(ifindex_g == 0) { perror("if_nametoindex"); return 1;}
    
    // Build the path to the BPF object file
    char bpf_obj_path[256];
    char *prog_dir = strdup(argv[0]);
    char *dir_path = dirname(prog_dir);
    snprintf(bpf_obj_path, sizeof(bpf_obj_path), "%s/packet_dropper.bpf.o", dir_path);
    free(prog_dir);
    
    bpf_obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(bpf_obj)) { return 1; }
    if (bpf_object__load(bpf_obj)) { bpf_object__close(bpf_obj); return 1; }
    ing_prog = bpf_object__find_program_by_name(bpf_obj, "handle_ingress");
    eg_prog = bpf_object__find_program_by_name(bpf_obj, "handle_egress");
    if (!ing_prog || !eg_prog) { fprintf(stderr, "Finding programs failed\n"); bpf_object__close(bpf_obj); return 1; }
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex_g, .attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS);
    int err = bpf_tc_hook_create(&hook);
    if (err && err != -EEXIST) { fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-err)); bpf_object__close(bpf_obj); return 1; }
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, ing_opts, .prog_fd = bpf_program__fd(ing_prog), .flags = BPF_TC_F_REPLACE);
    hook.attach_point = BPF_TC_INGRESS;
    err = bpf_tc_attach(&hook, &ing_opts);
    if (err) { fprintf(stderr, "Failed to attach ingress program: %s\n", strerror(-err)); cleanup(0); return 1; }
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, eg_opts, .prog_fd = bpf_program__fd(eg_prog), .flags = BPF_TC_F_REPLACE);
    hook.attach_point = BPF_TC_EGRESS;
    err = bpf_tc_attach(&hook, &eg_opts);
    if (err) { fprintf(stderr, "Failed to attach egress program: %s\n", strerror(-err)); cleanup(0); return 1; }
    map_fd = bpf_object__find_map_fd_by_name(bpf_obj, "state_map");
    if (map_fd < 0) { fprintf(stderr, "Finding map failed\n"); cleanup(0); return 1; }
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);


    // --- Main Logic: Choose loop based on mode ---
    if (mode == MODE_FIXED) {
        // --- Fixed Mode Loop ---
        __u32 key = 0;
        struct state fixed_state = { .packet_count = 0, .dropped_count = 0, .drop_probability = prob };
        if (bpf_map_update_elem(map_fd, &key, &fixed_state, BPF_ANY) != 0) {
            fprintf(stderr, "Error setting fixed probability in map.\n");
            cleanup(0);
            return 1;
        }
        // Fixed mode - just wait without printing stats
        while (1) {
            sleep(30); // Just keep the program alive
        }
    } else {
        // Dynamic mode - update drop probability based on packet rate
        last_time_ns = get_time_ns();
        while (1) {
            sleep(UPDATE_INTERVAL_SEC);
            __u32 key = 0;
            struct state current_state;
            if (bpf_map_lookup_elem(map_fd, &key, &current_state) != 0) { continue; }
            __u64 current_time_ns = get_time_ns();
            __u64 time_diff_ns = current_time_ns - last_time_ns;
            __u64 count_diff = current_state.packet_count - last_packet_count;
            last_time_ns = current_time_ns;
            last_packet_count = current_state.packet_count;
            double pps = (double)count_diff * 1e9 / time_diff_ns;
            __u32 new_prob = 0;
            if (pps > min_rate) {
                if (pps >= max_rate) { new_prob = max_prob; }
                else { new_prob = (__u32)(((pps - min_rate) / (max_rate - min_rate)) * max_prob); }
            }
            current_state.drop_probability = new_prob;
            bpf_map_update_elem(map_fd, &key, &current_state, BPF_ANY);
        }
    }

    return 0;
}
