#include <libdragon.h>
#include <stdio.h>

#include <t3d/t3d.h>
#include <t3d/t3dmath.h>

volatile uint32_t *MI_HW_INTR_MASK = ((volatile uint32_t *)0xA430003C);

#define NUM_FRAMEBUFFERS (3)

void rotate_matrix(T3DMat4 *matrix, T3DVec3 *angles) {
    T3DMat4 tempA, tempB;
    float siny, cosy, sinp, cosp;
    float yaw, pitch, roll;

    yaw = angles->v[0];
    pitch = angles->v[1];
    roll = angles->v[2];

    siny = fm_sinf(yaw);
    cosy = fm_cosf(yaw);

    sinp = fm_sinf(pitch);
    cosp = fm_cosf(pitch);

    // fm_sincosf(yaw, &siny, &cosy);
    // fm_sincosf(pitch, &sinp, &cosp);

    const T3DVec3 up = (T3DVec3){{0.0f, 1.0f, 0.0f}};
    const T3DVec3 left = (T3DVec3){{-1.0f, 0.0f, 0.0f}};
    const T3DVec3 back = (T3DVec3){{0.0f, 0.0f, -1.0f}};

    memcpy(&tempB, matrix, sizeof(tempB));

    t3d_mat4_rotate(&tempA, &back, roll);
    t3d_mat4_mul(matrix, &tempB, &tempA);

    t3d_mat4_rotate(&tempA, &left, pitch);
    t3d_mat4_mul(&tempB, matrix, &tempA);

    t3d_mat4_rotate(&tempA, &up, yaw);
    t3d_mat4_mul(matrix, &tempB, &tempA);
}

void translate_matrix(T3DMat4 *matrix, T3DVec3 *pos) {
    T3DMat4 tempA, tempB;

    memcpy(&tempB, matrix, sizeof(tempB));

    t3d_mat4_identity(&tempA);
    t3d_mat4_translate(&tempA, pos->v[0], pos->v[1], pos->v[2]);

    t3d_mat4_mul(matrix, &tempB, &tempA);
}

int main(void) {
    joypad_inputs_t inputs;

    surface_t depth_buffer;

    T3DMat4 model_matrix;
    T3DMat4FP *model_matrix_fp;

    T3DVec3 cam_pos = {{0, 0, -36}};
    T3DVec3 cam_rot = {{0.5f, 0.0f, 0.0f}};

    uint8_t ambient_colour[4] = {50, 50, 50, 0xFF};

    uint8_t colour_dir[4] = {0xFF, 0xFF, 0xFF, 0xFF};

    T3DVec3 light_dir = {{0.0f, 0.0f, 1.0f}};

    T3DVertPacked *vertices;

    uint16_t norm;

    T3DViewport viewport;

    rspq_block_t *dpl_draw = NULL;

    // ---------

    *MI_HW_INTR_MASK = (1 << 25);

    joypad_init();

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
        joypad_poll();

        inputs = joypad_get_inputs(JOYPAD_PORT_1);

        cam_rot.v[0] = ((float)inputs.stick_y / 85.0f) * M_TWOPI / 4.0f;
        cam_rot.v[1] = ((float)inputs.stick_x / 85.0f) * M_TWOPI / 4.0f;

        t3d_viewport_set_projection(&viewport, T3D_DEG_TO_RAD(85.0f), 10.0f, 100.0f);
        /*t3d_mat4_identity(&viewport.matCamera);
        t3d_mat4_to_fixed(&viewport._matCameraFP, &viewport.matCamera);
        data_cache_hit_writeback(&viewport._matCameraFP, sizeof(T3DMat4FP));*/
        // t3d_viewport_look_at(&viewport, &cam_pos, &(T3DVec3){{0, 0, 0}});
        // t3d_mat4_from_srt_euler(&viewport.matCamera, (T3DVec3){{1, 1, 1}}.v, (T3DVec3){{0, 0.5, 0}}.v, cam_pos.v);
        // t3d_mat4_identity(&viewport.matCamera);
        // translate_matrix(&viewport.matCamera, &cam_pos);
        t3d_mat4_from_srt_euler(&viewport.matCamera, (float[3]){1.0f, 1.0f, 1.0f}, cam_rot.v, (float[3]){0.0f, 0.0f, 0.0f});
        translate_matrix(&viewport.matCamera, &cam_pos);

        // cam_rot[1] += 0.1f;
        if (joypad_get_buttons_pressed(JOYPAD_PORT_1).c_right) {
            cam_rot.v[2] += M_TWOPI / 10.0f;
        }

        t3d_mat4_identity(&model_matrix);
        // rotate_matrix(&model_matrix, &cam_rot);
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