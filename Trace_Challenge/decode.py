import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

CSV_FILE = "traces.csv"
row_cols_1based = [4, 15, 14, 12, 17, 7, 8, 13]
col_cols_1based = [6, 2, 3, 5, 9, 16, 10, 11]

row_cols = [x - 2 for x in row_cols_1based]
col_cols = [x - 2 for x in col_cols_1based]

def load_csv(path: str) -> np.ndarray:
    df = pd.read_csv(path)
    arr = df.to_numpy()
    if arr.shape[1] == 17:
        arr = arr[:, 1:]
    elif arr.shape[1] != 16:
        raise ValueError(f"Expected 16 logic columns (or 17 incl. time), got {arr.shape[1]}")
    arr = (arr > 0.5).astype(np.uint8)
    return arr

def build_led_states(veri: np.ndarray) -> np.ndarray:
    n = veri.shape[0]
    led_states = np.zeros((8, 8, n), dtype=np.uint8)
    for i in range(n):
        for r in range(8):
            for c in range(8):
                if veri[i, row_cols[r]] == 1 and veri[i, col_cols[c]] == 1:
                    led_states[r, c, i] = 1
    return led_states

def animate_led_matrix(led_states: np.ndarray, pause_seconds: float = 0.2):
    n = led_states.shape[2]
    fig, ax = plt.subplots()
    img = ax.imshow(np.zeros((8, 8)), cmap="gray", interpolation="nearest")
    ax.set_title("LED Matrisi")
    ax.set_xticks([])
    ax.set_yticks([])

    def update(frame_idx):
        i = frame_idx + 7
        fid = (
            led_states[:, :, i - 7]
            + led_states[:, :, i - 6]
            + led_states[:, :, i - 5]
            + led_states[:, :, i - 4]
            + led_states[:, :, i - 3]
            + led_states[:, :, i - 2]
            + led_states[:, :, i - 1]
            + led_states[:, :, i]
        )
        fid_rot = np.rot90(fid)
        img.set_data(fid_rot)
        img.set_clim(vmin=0, vmax=8)
        ax.set_title(f"LED Matrisi - frame {i}")
        return [img]

    anim = FuncAnimation(
        fig,
        update,
        frames=max(0, n - 7),
        interval=int(pause_seconds * 1000),
        blit=True,
        repeat=False,
    )
    plt.show()

def save_mp4(led_states: np.ndarray, output_file: str = "matlab_like.mp4", fps: int = 5):
    n = led_states.shape[2]
    fig, ax = plt.subplots()
    img = ax.imshow(np.zeros((8, 8)), cmap="gray", interpolation="nearest")
    ax.set_title("LED Matrisi")
    ax.set_xticks([])
    ax.set_yticks([])

    def update(frame_idx):
        i = frame_idx + 7
        fid = (
            led_states[:, :, i - 7]
            + led_states[:, :, i - 6]
            + led_states[:, :, i - 5]
            + led_states[:, :, i - 4]
            + led_states[:, :, i - 3]
            + led_states[:, :, i - 2]
            + led_states[:, :, i - 1]
            + led_states[:, :, i]
        )
        fid_rot = np.rot90(fid)
        img.set_data(fid_rot)
        img.set_clim(vmin=0, vmax=8)
        ax.set_title(f"LED Matrisi - frame {i}")
        return [img]

    anim = FuncAnimation(
        fig,
        update,
        frames=max(0, n - 7),
        interval=int(1000 / fps),
        blit=True,
        repeat=False,
    )

    anim.save(output_file, writer="ffmpeg", fps=fps)
    plt.close(fig)
    print(f"Saved {output_file}")

def main():
    veri = load_csv(CSV_FILE)
    print("veri shape:", veri.shape)
    led_states = build_led_states(veri)
    print("led_states shape:", led_states.shape)
    animate_led_matrix(led_states, pause_seconds=0.2)

if __name__ == "__main__":
    main()
