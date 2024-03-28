#include <libdragon.h>
#include <stdio.h>

#include <t3d/t3d.h>
#include <t3d/t3dmath.h>

#define NUM_FRAMEBUFFERS (3)

int main(void) {
    surface_t depth_buffer;

    T3DMat4 model_matrix;
    T3DMat4FP *model_matrix_fp;

    T3DVec3 cam_pos = {{0, 0, -18}};
    float cam_rot[2] = {0.5f, 0.0f};

    uint8_t ambient_colour[4] = {50, 50, 50, 0xFF};

    uint8_t colour_dir[4] = {0xFF, 0xFF, 0xFF, 0xFF};

    T3DVec3 light_dir = {{0.0f, 0.0f, 1.0f}};

    T3DVertPacked *vertices;

    uint16_t norm;

    T3DViewport viewport;

    rspq_block_t *dpl_draw = NULL;

    // ---------

    display_init(RESOLUTION_640x480, DEPTH_16_BPP, NUM_FRAMEBUFFERS, GAMMA_NONE, FILTERS_RESAMPLE);

    depth_buffer = surface_alloc(FMT_RGBA16, display_get_width(), display_get_height());

    rdpq_init();

    t3d_init();

    t3d_mat4_identity(&model_matrix);

    model_matrix_fp = malloc_uncached(sizeof(T3DMat4FP));

    t3d_vec3_norm(&light_dir);

    vertices = malloc_uncached(sizeof(T3DVertPacked) * 2);

    norm = t3d_vert_pack_normal(&(T3DVec3){{0, 0, 1}});
    vertices[0] = (T3DVertPacked){
        .posA = {-16, -16, 0},
        .rgbaA = 0xFF0000'FF,
        .normA = norm,
        .posB = {16, -16, 0},
        .rgbaB = 0x00FF00'FF,
        .normB = norm,
    };
    vertices[1] = (T3DVertPacked){
        .posA = {16, 16, 0},
        .rgbaA = 0x0000FF'FF,
        .normA = norm,
        .posB = {-16, 16, 0},
        .rgbaB = 0xFF00FF'FF,
        .normB = norm,
    };

    viewport = t3d_viewport_create();

    while (1) {
        float sin, cos;
        fm_sincosf(cam_rot[0], &sin, &cos);

        const T3DVec3 up = (T3DVec3){{0.0f, 1.0f, 0.0f}};
        const T3DVec3 right = (T3DVec3){{-cos, 0.0f, sin}};

        t3d_viewport_set_projection(&viewport, T3D_DEG_TO_RAD(85.0f), 10.0f, 100.0f);
        /*t3d_mat4_identity(&viewport.matCamera);
        t3d_mat4_to_fixed(&viewport._matCameraFP, &viewport.matCamera);
        data_cache_hit_writeback(&viewport._matCameraFP, sizeof(T3DMat4FP));*/
        // t3d_viewport_look_at(&viewport, &cam_pos, &(T3DVec3){{0, 0, 0}});
        // t3d_mat4_from_srt_euler(&viewport.matCamera, (T3DVec3){{1, 1, 1}}.v, (T3DVec3){{0, 0.5, 0}}.v, cam_pos.v);
        t3d_mat4_identity(&viewport.matCamera);
        t3d_mat4_rotate(&viewport.matCamera, &up, cam_rot[0]);
        t3d_mat4_rotate(&viewport.matCamera, &right, cam_rot[1]);
        t3d_mat4_translate(&viewport.matCamera, cam_pos.v[0], cam_pos.v[1], cam_pos.v[2]);
        t3d_mat4_to_fixed(&viewport._matCameraFP, &viewport.matCamera);
        data_cache_hit_writeback(&viewport._matCameraFP, sizeof(T3DMat4FP));

        // cam_rot[1] += 0.1f;

        t3d_mat4_identity(&model_matrix);
        t3d_mat4_to_fixed(model_matrix_fp, &model_matrix);

        rdpq_attach(display_get(), &depth_buffer);
        t3d_frame_start();

        t3d_viewport_attach(&viewport);

        rdpq_mode_combiner(RDPQ_COMBINER_SHADE);
        t3d_screen_clear_color(RGBA32(100, 0, 100, 0));
        t3d_screen_clear_depth();

        t3d_light_set_ambient(ambient_colour);
        t3d_light_set_directional(0, colour_dir, &light_dir);
        t3d_light_set_count(1);

        t3d_state_set_drawflags(T3D_FLAG_SHADED | T3D_FLAG_DEPTH);

        if (dpl_draw == NULL) {
            rspq_block_begin();

            t3d_matrix_set_mul(model_matrix_fp, 1, 0);
            t3d_vert_load(vertices, 4);
            t3d_tri_draw(0, 1, 2);
            t3d_tri_draw(2, 3, 0);

            t3d_tri_sync();

            dpl_draw = rspq_block_end();
        }

        rspq_block_run(dpl_draw);

        rdpq_detach_show();
    }

    t3d_destroy();
}